"use strict";

const tauri = window.__TAURI__;
const invoke = tauri && tauri.core && typeof tauri.core.invoke === "function" ? tauri.core.invoke : null;

const REFRESH_MS = 2000;
const CONFIRM_MS = 4000;
const OVERVIEW_EVENTS = 8;
const PAGE_TITLES = {
  overview: "Overview",
  engines: "Engines",
  activity: "Activity",
  quarantine: "Quarantine",
  canaries: "Canaries",
  settings: "Settings",
};
const TOGGLE_FIELDS = {
  zip_bomb: "zip_bomb_enabled",
  bin_ai: "bin_ai_enabled",
  process_guard: "process_guard_enabled",
  canary: "canary_enabled",
  dry_run: "dry_run",
};
const RED_TYPES = new Set(["ZIP_BOMB", "RANSOMWARE_CANARY", "RANSOMWARE_SUSPECT", "MALWARE_AI", "MALWARE_AI_PROCESS"]);
const AMBER_TYPES = new Set(["LOTL_SCRIPT"]);
const GREEN_TYPES = new Set(["QUARANTINE_RESTORE"]);

const state = {
  page: "overview",
  query: "",
  severity: "ALL",
  dashboard: null,
  quarantine: [],
  refreshing: false,
  pendingToggles: new Set(),
  confirm: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.title) node.title = options.title;
  for (const [key, value] of Object.entries(options.attrs || {})) node.setAttribute(key, value);
  for (const child of children) node.append(child);
  return node;
}

function call(command, args) {
  if (!invoke) return Promise.reject(new Error("The Nex desktop runtime is not available in this window."));
  return invoke(command, args || {});
}

function errorText(error) {
  if (typeof error === "string") return error;
  return (error && error.message) || String(error);
}

let noticeTimer = null;
function notice(message, isError) {
  const box = $("notice");
  box.textContent = message;
  box.classList.toggle("error", Boolean(isError));
  box.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { box.hidden = true; }, isError ? 9000 : 5000);
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false });
}

function formatDateTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { hour12: false });
}

function formatShortDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function formatUptime(seconds) {
  if (seconds == null) return "";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function count(value) {
  return Number(value || 0).toLocaleString();
}

function shortPath(path) {
  const text = String(path || "");
  const separator = text.includes("\\") ? "\\" : "/";
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? text : parts.slice(-2).join(separator);
}

function fileName(path) {
  const parts = String(path || "").split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path || "");
}

function typeClass(type) {
  if (RED_TYPES.has(type)) return "pill red";
  if (AMBER_TYPES.has(type)) return "pill amber";
  if (GREEN_TYPES.has(type)) return "pill green";
  return "pill";
}

function actionLabel(action) {
  const text = String(action || "");
  if (text.startsWith("DRY_RUN")) return "Dry run";
  if (text.includes("QUARANTINE_FAILED") || text === "TERMINATE_FAILED") return "Failed";
  if (text.startsWith("TERMINATED") && text.includes("QUARANTINED")) return "Terminated + quarantined";
  if (text.startsWith("QUARANTINED")) return "Quarantined";
  if (text.startsWith("TERMINATED")) return "Terminated";
  if (text === "ALERT_RAISED") return "Alerted";
  if (text === "RESTORED") return "Restored";
  if (text === "DELETED") return "Deleted";
  const word = text.split(/[\s=]/)[0].replace(/_/g, " ");
  return word ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() : "—";
}

function eventRow(event, withSeverity) {
  const cells = [
    el("td", { text: formatTime(event.timestamp), title: formatDateTime(event.timestamp) }),
    el("td", {}, [el("span", { className: typeClass(event.threat_type), text: event.threat_type })]),
  ];
  if (withSeverity) cells.push(el("td", { text: event.severity }));
  cells.push(
    el("td", { text: shortPath(event.target), title: event.target }),
    el("td", { text: event.details, title: event.details }),
    el("td", { text: actionLabel(event.action_taken), title: event.action_taken }),
  );
  return el("tr", {}, cells);
}

function setSwitch(button, checked) {
  button.setAttribute("aria-checked", checked ? "true" : "false");
}

function renderToggles(toggles, enabled) {
  for (const button of document.querySelectorAll(".switch[data-engine]")) {
    const engine = button.dataset.engine;
    if (state.pendingToggles.has(engine)) continue;
    setSwitch(button, Boolean(toggles && toggles[TOGGLE_FIELDS[engine]]));
    button.disabled = !enabled;
  }
}

function buildEngineRows() {
  const rows = $("engine-rows");
  const engines = [
    ["zip_bomb", "Zip Bomb Guard", "Central-directory inspection before extraction: ratio, size, overlap and nesting."],
    ["bin_ai", "ONNX Binary AI", "Scores new PE and Mach-O files and processes with the local tract model."],
    ["process_guard", "LotL Process Guard", "Terminates script hosts and shells launched with download or obfuscation patterns."],
    ["canary", "Canary Honeypots", "Decoy documents that reveal ransomware the moment they change."],
  ];
  for (const [engine, title, description] of engines) {
    const thresholds = el("div", { className: "thresholds", attrs: { "data-thresholds": engine } });
    rows.append(el("div", { className: "row" }, [
      el("div", {}, [el("h3", { text: title }), el("p", { className: "muted", text: description }), thresholds]),
      el("button", { className: "switch", attrs: { role: "switch", "aria-checked": "false", "data-engine": engine, "aria-label": title } }),
    ]));
  }
}

function fillThresholds(engine, values) {
  const holder = document.querySelector(`[data-thresholds="${engine}"]`);
  if (!holder) return;
  holder.replaceChildren(...values.map((value) => el("span", { className: "pill", text: value })));
}

function facts(list, entries) {
  list.replaceChildren(...entries.flatMap(([term, value]) => [el("dt", { text: term }), el("dd", { text: value })]));
}

function renderDashboard(d) {
  const online = d.daemon.online;
  const footerDot = $("service-dot");
  footerDot.className = online ? "dot ok" : "dot";
  $("service-text").textContent = online
    ? `Service Active · ${(d.daemon.memory_mb || 0).toFixed(1)} MB`
    : "Daemon Offline";

  const protection = $("protection-dot");
  if (!online) {
    protection.className = "dot bad";
    $("protection-text").textContent = "Unprotected — Service Offline";
  } else if (d.dry_run) {
    protection.className = "dot warn";
    $("protection-text").textContent = "Dry Run — Detect Only";
  } else {
    protection.className = "dot ok";
    $("protection-text").textContent = "Protected — Local Rust Engine";
  }
  $("stat-scanned").textContent = count(d.scanned);
  $("stat-quarantined").textContent = count(d.quarantined);
  $("stat-cpu").textContent = online ? `${(d.daemon.cpu_percent || 0).toFixed(1)}%` : "—";

  const badge = $("quarantine-badge");
  badge.textContent = String(d.quarantined);
  badge.hidden = d.quarantined === 0;

  const t = d.thresholds;
  $("card-zip").textContent = `Ratio >${t.max_ratio}:1 · Depth ≤${t.max_depth} · Pre-extraction`;
  let model;
  if (d.model_loaded) model = "thenex_model.onnx · Offline · Local tract";
  else if (d.model_present) model = "thenex_model.onnx · Loads with the service";
  else model = "Model missing · Heuristic fallback";
  $("card-ai").textContent = model;
  $("card-lotl").textContent = `${count(d.processes_watched)} processes watched · Shell & Script Shield`;
  $("card-canary").textContent = `${d.canaries_intact} decoy file${d.canaries_intact === 1 ? "" : "s"} intact · Desktop & Docs`;
  renderToggles(d.toggles, true);

  fillThresholds("zip_bomb", [
    `ratio > ${t.max_ratio}:1 above ${t.min_ratio_check_mb} MB`,
    `size ≤ ${t.max_uncompressed_gb} GB`,
    `depth ≤ ${t.max_depth}`,
    `nested read ≤ ${t.nested_read_mb} MB`,
  ]);
  fillThresholds("bin_ai", [`malicious ≥ ${t.ai_threshold}`, d.model_loaded ? "onnx" : "heuristic"]);
  fillThresholds("process_guard", [`${count(d.processes_watched)} watched`, `${count(d.processes_inspected)} inspected`]);
  fillThresholds("canary", [`${d.canaries_intact}/${d.canaries.length} intact`, "2s self-write cooldown"]);

  facts($("model-facts"), [
    ["Model file", d.model_path],
    ["Present", d.model_present ? "yes" : "no"],
    ["Service engine", online ? (d.model_loaded ? "ONNX (tract)" : "heuristic fallback") : "service offline"],
    ["Decision threshold", String(t.ai_threshold)],
  ]);

  renderCanaries(d.canaries);

  $("service-state").textContent = d.service_installed
    ? (online ? "Installed · running" : "Installed · not running")
    : "Not installed";
  $("service-detail").textContent = online
    ? `PID ${d.daemon.pid} · v${d.daemon.version} · up ${formatUptime(d.daemon.uptime_seconds)} · ${(d.daemon.memory_mb || 0).toFixed(1)} MB`
    : "The engine is not running in the background.";
  $("install-service").textContent = d.service_installed ? "Reinstall" : "Install";
  $("uninstall-service").disabled = !d.service_installed;

  $("watched-dirs").replaceChildren(...(d.watched_dirs.length
    ? d.watched_dirs.map((dir) => el("li", { text: dir }))
    : [el("li", { className: "muted", text: "No watched folders found." })]));
  facts($("data-facts"), [
    ["Data folder", d.data_dir],
    ["Event log", d.events_log],
    ["Settings", d.settings_file],
    ["Platform", d.platform],
  ]);
}

function renderOffline(reason) {
  $("service-dot").className = "dot";
  $("service-text").textContent = "Daemon Offline";
  $("protection-dot").className = "dot bad";
  $("protection-text").textContent = reason;
  renderToggles(null, false);
  for (const id of ["quick-scan", "verify-canaries", "install-service", "uninstall-service"]) $(id).disabled = true;
}

function matchesQuery(...fields) {
  if (!state.query) return true;
  const query = state.query.toLowerCase();
  return fields.some((field) => String(field || "").toLowerCase().includes(query));
}

// Rebuilding rows on every 2 s poll would swallow clicks that straddle a rebuild, so only
// replace a table body when what it shows has changed.
function replaceIfChanged(node, signature, build) {
  if (node.dataset.signature === signature) return;
  node.dataset.signature = signature;
  node.replaceChildren(...build());
}

function renderCanaries(canaries) {
  const shown = canaries.filter((c) => matchesQuery(c.path, c.state));
  replaceIfChanged($("canary-rows"), JSON.stringify(shown.map((c) => [c.path, c.state])), () => shown.map((c) => el("tr", {}, [
    el("td", { text: c.path, title: c.path }),
    el("td", {}, [el("span", { className: c.state === "Intact" ? "pill green" : "pill red", text: c.state })]),
  ])));
  $("canary-empty").hidden = shown.length > 0;
}

function confirming(action, id) {
  return state.confirm && state.confirm.action === action && state.confirm.id === id && Date.now() < state.confirm.until;
}

function quarantineButton(action, label, id) {
  const armed = confirming(action, id);
  const button = el("button", {
    className: action === "delete" ? "btn btn-small btn-danger" : "btn btn-small",
    text: armed ? `Confirm ${label.toLowerCase()}` : label,
  });
  button.addEventListener("click", () => quarantineAction(action, id));
  return button;
}

function renderQuarantine() {
  const records = state.quarantine.filter((q) => matchesQuery(q.id, q.original_path, q.sha256, q.threat_type, q.details));
  const signature = JSON.stringify(records.map((q) => [q.id, confirming("restore", q.id), confirming("delete", q.id)]));
  replaceIfChanged($("quarantine-rows"), signature, () => records.map((q) => el("tr", {}, [
    el("td", { text: formatShortDate(q.quarantined_at), title: formatDateTime(q.quarantined_at) }),
    el("td", { text: fileName(q.original_path), title: q.original_path }),
    el("td", {}, [el("span", { className: typeClass(q.threat_type), text: q.threat_type, title: q.details })]),
    el("td", { text: `${q.sha256.slice(0, 16)}…`, title: q.sha256 }),
    el("td", { className: "right" }, [
      el("div", { className: "button-group", attrs: { style: "justify-content:flex-end" } }, [
        quarantineButton("restore", "Restore", q.id),
        quarantineButton("delete", "Delete", q.id),
      ]),
    ]),
  ])));
  $("quarantine-empty").hidden = records.length > 0;
  $("quarantine-count").textContent = `${state.quarantine.length} file${state.quarantine.length === 1 ? "" : "s"}`;
}

async function quarantineAction(action, id) {
  if (!confirming(action, id)) {
    state.confirm = { action, id, until: Date.now() + CONFIRM_MS };
    renderQuarantine();
    setTimeout(renderQuarantine, CONFIRM_MS + 50);
    return;
  }
  state.confirm = null;
  try {
    const message = await call(action === "restore" ? "restore_quarantine" : "delete_quarantine", { id });
    notice(message, false);
  } catch (error) {
    notice(errorText(error), true);
  }
  await refresh(true);
}

async function loadEvents() {
  const overview = await call("get_events", { limit: OVERVIEW_EVENTS, query: state.query || null, severity: "ALL" });
  const eventsSignature = (events) => events.map((e) => `${e.id}|${e.timestamp}`).join(",");
  replaceIfChanged($("overview-events"), eventsSignature(overview), () => overview.map((e) => eventRow(e, false)));
  $("overview-empty").hidden = overview.length > 0;
  if (state.page === "activity") {
    const all = await call("get_events", { limit: 1000, query: state.query || null, severity: state.severity });
    replaceIfChanged($("activity-events"), eventsSignature(all), () => all.map((e) => eventRow(e, true)));
    $("activity-empty").hidden = all.length > 0;
  }
}

async function refresh(force) {
  if (state.refreshing && !force) return;
  state.refreshing = true;
  try {
    state.dashboard = await call("get_dashboard_state");
    renderDashboard(state.dashboard);
    for (const id of ["quick-scan", "verify-canaries", "install-service"]) {
      if (!$(id).dataset.busy) $(id).disabled = false;
    }
    await loadEvents();
    state.quarantine = await call("list_quarantine").catch((error) => {
      if (state.page === "quarantine") notice(errorText(error), true);
      return state.quarantine;
    });
    renderQuarantine();
  } catch (error) {
    renderOffline(invoke ? `Unavailable — ${errorText(error)}` : "Open The Nex from its desktop app to manage protection.");
  } finally {
    state.refreshing = false;
  }
}

async function busy(buttonId, label, work) {
  const button = $(buttonId);
  const original = button.textContent;
  button.dataset.busy = "1";
  button.disabled = true;
  button.textContent = label;
  try {
    await work();
  } catch (error) {
    notice(errorText(error), true);
  } finally {
    delete button.dataset.busy;
    button.disabled = false;
    button.textContent = original;
    await refresh(true);
  }
}

function showPage(page) {
  state.page = page;
  for (const item of document.querySelectorAll(".nav-item")) item.classList.toggle("active", item.dataset.page === page);
  for (const section of document.querySelectorAll(".page")) section.classList.toggle("active", section.id === `page-${page}`);
  $("page-title").textContent = PAGE_TITLES[page];
  refresh(true);
}

async function toggleEngine(button) {
  const engine = button.dataset.engine;
  const enabled = button.getAttribute("aria-checked") !== "true";
  state.pendingToggles.add(engine);
  for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) setSwitch(twin, enabled);
  try {
    const toggles = await call("toggle_engine", { engine, enabled });
    state.pendingToggles.delete(engine);
    renderToggles(toggles, true);
  } catch (error) {
    state.pendingToggles.delete(engine);
    for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) setSwitch(twin, !enabled);
    notice(errorText(error), true);
  }
  await refresh(true);
}

function wire() {
  buildEngineRows();
  for (const item of document.querySelectorAll(".nav-item")) item.addEventListener("click", () => showPage(item.dataset.page));
  for (const link of document.querySelectorAll("[data-goto]")) link.addEventListener("click", () => showPage(link.dataset.goto));
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".switch[data-engine]");
    if (button && !button.disabled) toggleEngine(button);
  });
  for (const pill of document.querySelectorAll(".pill-filter")) {
    pill.addEventListener("click", () => {
      state.severity = pill.dataset.severity;
      for (const other of document.querySelectorAll(".pill-filter")) other.classList.toggle("active", other === pill);
      refresh(true);
    });
  }

  const search = $("search");
  let searchTimer = null;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = search.value.trim();
      refresh(true);
    }, 150);
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      search.value = "";
      state.query = "";
      search.blur();
      refresh(true);
    }
  });
  const mac = /Mac/i.test(navigator.platform || navigator.userAgent);
  $("search-hint").textContent = mac ? "⌘ K" : "Ctrl K";
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      search.focus();
      search.select();
    }
  });

  $("quick-scan").addEventListener("click", () => busy("quick-scan", "Scanning…", async () => {
    const report = await call("run_quick_scan");
    const threats = report.findings.length;
    const mode = report.dry_run ? " (dry run)" : "";
    notice(`Quick scan${mode}: ${count(report.files_scanned)} of ${count(report.files_examined)} files inspected, ${threats} threat${threats === 1 ? "" : "s"} found.`, threats > 0);
  }));
  $("verify-canaries").addEventListener("click", () => busy("verify-canaries", "Verifying…", async () => {
    const canaries = await call("verify_canaries");
    const intact = canaries.filter((c) => c.state === "Intact").length;
    notice(`${intact} of ${canaries.length} canary files intact.`, intact !== canaries.length);
  }));
  $("install-service").addEventListener("click", () => busy("install-service", "Installing…", async () => {
    notice(await call("install_service"), false);
  }));
  $("uninstall-service").addEventListener("click", () => busy("uninstall-service", "Removing…", async () => {
    notice(await call("uninstall_service"), false);
  }));
}

wire();
refresh(true);
setInterval(() => refresh(false), REFRESH_MS);
