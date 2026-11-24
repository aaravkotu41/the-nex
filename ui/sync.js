"use strict";
// Device sync + remote actions for The Nex over Supabase PostgREST (RLS-protected, see migration `device_sync`).
// One global: window.NexSync. Pure logic first (testable in a vm, see scripts/test_sync.js); DOM wiring at the bottom.
// Remote actions are an allowlist of two: quick_scan (quarantines threats when dry run is off) and
// verify_canaries (rewrites the decoy files). Neither can switch protection off.
(function () {
  const KEY = "thenex.device."; // + user id: a different account never reuses this device record
  const HEARTBEAT_MS = 60000;
  const POLL_MS = 15000;
  const BACKOFF_MS = 60000;
  const COMMAND_TTL_MS = 10 * 60 * 1000;
  const ONLINE_MS = 3 * 60 * 1000;
  const ALLOWED = { quick_scan: "run_quick_scan", verify_canaries: "verify_canaries" };

  let callApi = null;
  let device = null;
  let hbTimer = null;
  let pollTimer = null;
  let running = false;
  let skew = 0; // server clock minus local clock (ms), from the Date response header
  let syncError = ""; // last server-side rejection of our heartbeat (device cap, rate limit)
  let gen = 0; // bumped by start/stop so stale async loops end quietly
  const lastClick = new Map();

  const cfg = () => window.NEX_SUPABASE || {};
  const nowSec = () => Math.floor(Date.now() / 1000);
  const serverNow = () => Date.now() + skew;
  const errText = (r) => (r.offline ? "Can't reach the sync service." : (r.data && typeof r.data.message === "string" && r.data.message) || "Request failed (HTTP " + r.status + ").");

  // Trim, drop control and bidi/zero-width chars, collapse spaces, cap at 60. -> string or null when empty.
  function sanitizeName(raw) {
    const s = String(raw == null ? "" : raw).replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, "").replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/\s+/g, " ").trim();
    const t = Array.from(s).slice(0, 60).join("").trim();
    return t || null;
  }
  function normPlatform(p) {
    const s = String(p || "").toLowerCase();
    return /win/.test(s) ? "windows" : /mac|darwin/.test(s) ? "macos" : /linux/.test(s) ? "linux" : "unknown";
  }
  const PLATFORM_LABEL = { windows: "Windows", macos: "macOS", linux: "Linux", unknown: "Unknown" };

  // Data minimisation: counts and flags only. No paths, no event details.
  function heartbeatPayload(dash, dev) {
    const d = dash || {};
    const t = d.toggles || {};
    const canaries = Array.isArray(d.canaries) ? d.canaries : [];
    const num = (n) => (Number.isFinite(n) ? n : 0);
    return {
      id: dev.id,
      name: dev.name,
      platform: normPlatform(d.platform),
      app_version: String((d.daemon && d.daemon.version) || "").slice(0, 32) || null,
      status: {
        online: !!(d.daemon && d.daemon.online),
        dry_run: !!d.dry_run,
        engines_total: 5,
        engines_on: ["known_bad_enabled", "zip_bomb_enabled", "bin_ai_enabled", "process_guard_enabled", "canary_enabled"].filter((k) => t[k] && (k !== "known_bad_enabled" || (d.known_bad && d.known_bad.loaded))).length,
        threats_detected: num(d.threats_detected),
        quarantined: num(d.quarantined),
        canaries_intact: num(d.canaries_intact),
        canaries_total: canaries.length,
      },
      last_seen: new Date().toISOString(),
    };
  }

  let uid = "";
  const key = () => KEY + uid;

  function loadDevice() {
    try {
      const d = JSON.parse(localStorage.getItem(key()) || "null");
      if (d && typeof d.id === "string" && /^[0-9a-f-]{36}$/i.test(d.id)) return { id: d.id, name: sanitizeName(d.name) || "" };
    } catch { /* unreadable or blocked */ }
    return null;
  }
  function saveDevice() {
    try { localStorage.setItem(key(), JSON.stringify({ id: device.id, name: device.name })); } catch { /* id lasts this session only */ }
  }

  // -> { ok, status, data } | { ok:false, offline:true } | { ok:false, status }. One refresh on 401, then give up.
  async function rest(method, path, body, prefer) {
    const c = cfg();
    const auth = window.NexAuth;
    if (!auth || !c.url || !c.publishableKey) return { ok: false, status: 0 };
    let s = auth.getSession();
    if (!s || s.expires_at - nowSec() < 30) {
      const r = await auth.refresh();
      if (!r.ok) return { ok: false, offline: !!r.offline, status: 0 };
      s = auth.getSession();
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers = { apikey: c.publishableKey, Authorization: "Bearer " + s.access_token };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (prefer) headers.Prefer = prefer;
      let res;
      try {
        res = await fetch(String(c.url).replace(/\/+$/, "") + "/rest/v1/" + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined });
      } catch {
        return { ok: false, offline: true };
      }
      const date = Date.parse(res.headers && res.headers.get ? res.headers.get("Date") : "");
      if (Number.isFinite(date)) skew = date - Date.now();
      if (res.status === 401 && attempt === 0) {
        const r = await auth.refresh();
        if (!r.ok) return { ok: false, status: 401 };
        s = auth.getSession();
        continue;
      }
      let data = null;
      try { data = await res.json(); } catch { /* empty body */ }
      return { ok: res.ok, status: res.status, data };
    }
    return { ok: false, status: 401 };
  }

  async function heartbeat() {
    let dash;
    try { dash = await callApi("get_dashboard_state"); } catch { return { ok: false }; }
    if (!device.name) { device.name = PLATFORM_LABEL[normPlatform(dash && dash.platform)] + " device"; saveDevice(); }
    const r = await rest("POST", "devices", heartbeatPayload(dash, device), "resolution=merge-duplicates,return=minimal");
    syncError = r.ok || r.offline || !r.status ? "" : errText(r);
    return r;
  }

  const patch = (id, filter, fields) =>
    rest("PATCH", "device_commands?id=eq." + encodeURIComponent(id) + filter, fields, "return=representation");

  async function execute(cmd) {
    const out = await callApi(ALLOWED[cmd.command], { remote: true }); // lets the backend refuse elevation for remote runs
    if (cmd.command === "quick_scan") {
      return { threats: (out.findings || []).length, files_scanned: out.files_scanned || 0, duration_ms: out.duration_ms || 0, blocked: (out.unreadable || []).length };
    }
    const list = Array.isArray(out) ? out : [];
    return { intact: list.filter((c) => c.state === "Intact").length, total: list.length };
  }

  // One pass over this device's pending commands. -> true when the server answered.
  async function pollOnce() {
    if (running) return true;
    running = true;
    try {
      const r = await rest("GET", "device_commands?select=*&device_id=eq." + encodeURIComponent(device.id) + "&status=eq.pending&order=created_at.asc");
      if (!r.ok || !Array.isArray(r.data)) return false;
      for (const cmd of r.data) {
        const age = serverNow() - Date.parse(cmd.created_at);
        const done = (status, result) => patch(cmd.id, "&status=eq." + (status === "expired" || !ALLOWED[cmd.command] ? "pending" : "running"), { status, result, completed_at: new Date().toISOString() });
        if (!(age <= COMMAND_TTL_MS)) { await done("expired", null); continue; }
        if (!Object.prototype.hasOwnProperty.call(ALLOWED, cmd.command)) { await done("failed", { error: "unsupported" }); continue; }
        const claim = await patch(cmd.id, "&status=eq.pending", { status: "running" });
        if (!claim.ok || !Array.isArray(claim.data) || claim.data.length === 0) continue; // someone else has it
        try { await done("done", await execute(cmd)); } catch (e) { await done("failed", { error: String((e && e.message) || e).slice(0, 200) }); }
      }
      return true;
    } finally { running = false; }
  }

  // A crash mid-run leaves commands stuck in `running`; retire this device's own after the TTL.
  const expireStuck = () => rest("PATCH", "device_commands?device_id=eq." + encodeURIComponent(device.id) + "&status=eq.running&created_at=lt." + encodeURIComponent(new Date(serverNow() - COMMAND_TTL_MS).toISOString()),
    { status: "expired", result: null, completed_at: new Date(serverNow()).toISOString() }, "return=minimal");

  function loop(g, ms) {
    pollTimer = setTimeout(async () => {
      if (g !== gen) return;
      let ok = false;
      try { ok = await pollOnce(); } catch { /* keep going */ }
      if (g === gen) loop(g, ok ? POLL_MS : BACKOFF_MS);
    }, ms);
  }

  function start(api) {
    stop();
    callApi = api;
    const u = window.NexAuth && window.NexAuth.getSession();
    uid = String((u && u.user && u.user.id) || "");
    try { localStorage.removeItem("thenex.device"); } catch { /* pre-account record, unused now */ }
    device = loadDevice() || { id: crypto.randomUUID(), name: "" };
    const g = gen;
    saveDevice();
    heartbeat().then(() => expireStuck()).then(() => { if (g === gen) loop(g, 0); }).catch(() => { if (g === gen) loop(g, BACKOFF_MS); });
    hbTimer = setInterval(() => { heartbeat().catch(() => {}); }, HEARTBEAT_MS);
  }
  function stop() {
    gen++;
    clearInterval(hbTimer); clearTimeout(pollTimer);
    hbTimer = pollTimer = null;
  }

  // At most one click per second per key.
  function allow(key) {
    const t = Date.now();
    if (t - (lastClick.get(key) || 0) < 1000) return false;
    lastClick.set(key, t);
    return true;
  }

  async function rename(raw) {
    const name = sanitizeName(raw);
    if (!name || !device || !allow("rename")) return null;
    device.name = name;
    saveDevice();
    await heartbeat();
    return name;
  }

  async function listDevices() {
    const [d, c, o] = await Promise.all([
      rest("GET", "devices?select=*&order=last_seen.desc"),
      rest("GET", "device_commands?select=*&order=created_at.desc&limit=20"),
      rest("GET", "device_commands?select=device_id&status=in.(pending,running)&created_at=gt." + encodeURIComponent(new Date(serverNow() - COMMAND_TTL_MS).toISOString())),
    ]);
    if (!d.ok || !Array.isArray(d.data)) return { error: d.offline ? "Can't reach the sync service." : "Couldn't load devices." };
    return {
      devices: d.data,
      commands: c.ok && Array.isArray(c.data) ? c.data : [],
      open: o.ok && Array.isArray(o.data) ? [...new Set(o.data.map((x) => x.device_id))] : [],
      warning: syncError,
    };
  }

  async function sendCommand(deviceId, command) {
    if (!Object.prototype.hasOwnProperty.call(ALLOWED, command)) return { ok: false, error: "Unsupported command." };
    if (!allow("cmd:" + deviceId)) return { ok: false, error: "Slow down: one request per second." };
    const r = await rest("POST", "device_commands", { device_id: deviceId, command }, "return=minimal");
    if (r.ok) return { ok: true };
    return { ok: false, error: errText(r) };
  }

  // Deletes another device's record. Never this device.
  async function removeDevice(id) {
    if (!device || id === device.id) return { ok: false, error: "This device can't remove itself." };
    if (!allow("rm:" + id)) return { ok: false, error: "Slow down: one request per second." };
    const r = await rest("DELETE", "devices?id=eq." + encodeURIComponent(id), undefined, "return=minimal");
    return r.ok ? { ok: true } : { ok: false, error: errText(r) };
  }

  const isOnline = (lastSeen) => serverNow() - Date.parse(lastSeen) < ONLINE_MS;

  window.NexSync = {
    start, stop, sanitizeName, heartbeatPayload, pollOnce, heartbeat, rename, allow, listDevices, sendCommand, removeDevice, isOnline,
    thisDeviceId: () => (device ? device.id : null),
    thisDeviceName: () => (device ? device.name : ""),
  };

  // ---- DOM wiring (skipped in tests) ----
  if (typeof document === "undefined") return;

  const COMMAND_LABEL = { quick_scan: "Quick scan", verify_canaries: "Canary check" };
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function ago(iso) {
    const s = Math.max(0, (serverNow() - Date.parse(iso)) / 1000);
    if (!Number.isFinite(s)) return "unknown";
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 129600) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function protection(st) {
    if (!st.online) return ["Service offline", "red"];
    if (st.dry_run) return ["Dry run", "amber"];
    const total = st.engines_total || 4;
    if (st.engines_on === total) return ["Protected", "green"];
    return [st.engines_on + " of " + total + " engines on", st.engines_on ? "amber" : "red"];
  }
  function commandLine(c) {
    const r = c.result || {};
    let tail = "";
    if (c.status === "done" && c.command === "quick_scan") tail = ": " + r.threats + (r.threats === 1 ? " threat, " : " threats, ") + r.files_scanned + " files, " + (r.duration_ms / 1000).toFixed(1) + " s" + (r.blocked ? ", " + r.blocked + " folder(s) blocked by macOS" : "");
    else if (c.status === "done") tail = ": " + r.intact + " of " + r.total + " intact";
    else if (c.status === "pending") tail = ": waiting for the device";
    else if (c.status === "failed" && r.error) tail = ": " + r.error;
    return (COMMAND_LABEL[c.command] || "Command") + " " + c.status + tail + ", " + ago(c.created_at);
  }


  const CONFIRM_MS = 5000;
  const msgs = new Map(); // deviceId -> last action error
  const inflight = new Set();
  const ui = { editing: null, editValue: "", armed: null }; // armed: { id, at } for the two-step Remove

  const announce = (text) => { const n = document.getElementById("devices-status"); if (n) n.textContent = text; };
  const armedId = () => (ui.armed && Date.now() - ui.armed.at < CONFIRM_MS ? ui.armed.id : null);

  function button(label, key, onClick, opts) {
    const b = el("button", "btn btn-small" + (opts && opts.danger ? " btn-danger" : ""), label);
    b.type = "button";
    b.dataset.key = key;
    b.disabled = !!(opts && opts.disabled);
    b.addEventListener("click", onClick);
    return b;
  }

  async function saveRename(d) {
    const name = await rename(ui.editValue);
    if (!name) { msgs.set(d.id, "Enter a name of 1 to 60 characters, one change per second."); return render("rename-input:" + d.id); }
    ui.editing = null; msgs.delete(d.id);
    announce("Device renamed to " + name + ".");
    await refreshList(true, "rename:" + d.id);
  }

  async function onRemove(e, d) {
    if (armedId() !== d.id) {
      ui.armed = { id: d.id, at: Date.now() };
      render("remove:" + d.id);
      setTimeout(() => render(), CONFIRM_MS + 50);
      return;
    }
    if (e.detail > 1 || Date.now() - ui.armed.at < 400) return; // a double-click must not confirm
    ui.armed = null; msgs.delete(d.id);
    const r = await removeDevice(d.id);
    if (r.ok) announce("Device removed."); else { msgs.set(d.id, r.error); announce(r.error); }
    await refreshList(true);
  }

  function row(d, data, mine) {
    const st = d.status || {};
    const online = isOnline(d.last_seen);
    const latest = data.commands.find((c) => c.device_id === d.id);
    const open = data.open.includes(d.id);
    const [plabel, tone] = protection(st);

    const head = el("div", "dev-head");
    const title = el("div", "dev-title");
    title.append(el("h3", null, sanitizeName(d.name) || "Unnamed device"));
    if (mine) title.append(el("span", "pill green", "This device"));
    head.append(title, el("span", "pill status " + (online ? "green" : ""), online ? "Online" : "Last seen " + ago(d.last_seen)));

    const facts = el("div", "dev-facts");
    facts.append(
      el("span", "muted", (PLATFORM_LABEL[d.platform] || "Unknown") + (d.app_version ? " · v" + d.app_version : "")),
      el("span", "pill " + tone, plabel),
      el("span", "muted", (st.threats_detected || 0) + " threats · " + (st.quarantined || 0) + " quarantined"),
    );

    const actions = el("div", "button-group");
    if (mine && ui.editing === d.id) {
      const input = el("input", "text-input");
      input.type = "text"; input.maxLength = 60; input.value = ui.editValue;
      input.setAttribute("aria-label", "Device name");
      input.dataset.key = "rename-input:" + d.id;
      input.addEventListener("input", () => { ui.editValue = input.value; });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") { e.preventDefault(); saveRename(d); }
        else if (e.key === "Escape") { ui.editing = null; render("rename:" + d.id); }
      });
      actions.append(input,
        button("Save", "save:" + d.id, () => saveRename(d)),
        button("Cancel", "cancel:" + d.id, () => { ui.editing = null; render("rename:" + d.id); }));
    } else {
      for (const [cmd, label] of [["quick_scan", "Run quick scan"], ["verify_canaries", "Verify canaries"]]) {
        actions.append(button(label, cmd + ":" + d.id, async () => {
          inflight.add(d.id); msgs.delete(d.id);
          const r = await sendCommand(d.id, cmd);
          inflight.delete(d.id);
          if (!r.ok) msgs.set(d.id, r.error);
          announce(r.ok ? label + " requested." : r.error);
          await refreshList(true);
        }, { disabled: open || inflight.has(d.id) }));
      }
      if (mine) {
        actions.append(button("Rename", "rename:" + d.id, () => { ui.editing = d.id; ui.editValue = d.name || ""; render("rename-input:" + d.id); }));
      } else {
        const armed = armedId() === d.id;
        actions.append(button(armed ? "Confirm remove" : "Remove", "remove:" + d.id, (e) => onRemove(e, d), { danger: armed }));
      }
    }

    const card = el("div", "dev-row");
    card.append(head, facts, actions);
    if (!mine && armedId() === d.id) card.append(el("p", "dev-msg muted", "If that computer is still signed in, it will reappear the next time it checks in."));
    if (msgs.has(d.id)) card.append(el("p", "dev-msg error", msgs.get(d.id)));
    if (latest) card.append(el("p", "dev-msg muted", commandLine(latest)));
    return card;
  }

  let last = null;
  let lastSig = "";
  // Rebuilds only when data or UI state changed, and puts focus back on the same control (data-key).
  function render(focusKey) {
    const box = document.getElementById("devices-list");
    if (!box) return;
    const sig = JSON.stringify([last, [...msgs], [...inflight], ui.editing, armedId()]);
    if (sig === lastSig) return;
    lastSig = sig;
    const key = focusKey || (document.activeElement && box.contains(document.activeElement) && document.activeElement.dataset.key);
    box.replaceChildren();
    if (!last) return;
    if (last.error) { box.append(el("p", "empty", last.error)); return; }
    if (last.warning) box.append(el("p", "dev-msg error", last.warning));
    box.append(...last.devices.map((d) => row(d, last, d.id === (device && device.id))));
    if (last.devices.length <= 1) box.append(el("p", "empty", "Only this device so far. Sign in on another computer to see it here."));
    const target = key && box.querySelector('[data-key="' + key + '"]');
    if (target) target.focus();
  }

  async function refreshList(force, focusKey) {
    const page = document.getElementById("page-devices");
    if (!device || !page || !page.classList.contains("active") || document.hidden) return;
    if (!force && ui.editing) return; // don't poll under an open rename field
    last = await listDevices();
    render(focusKey);
  }
  setInterval(() => refreshList(), POLL_MS);
  document.addEventListener("click", (e) => {
    const item = e.target.closest && e.target.closest('.nav-item[data-page="devices"]');
    if (item) setTimeout(refreshList, 0);
  });
})();
