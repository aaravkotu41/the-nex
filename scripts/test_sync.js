#!/usr/bin/env node
// Tests for ui/sync.js (device sync + remote actions) in a vm with fake fetch/auth/localStorage.
// Run: node scripts/test_sync.js  (exit 1 on failure)
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const src = fs.readFileSync(path.join(__dirname, "..", "ui", "sync.js"), "utf8");

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures++;
}

// handler(url, opts) -> {status, body}
function env(handler, cfg = {}) {
  const calls = [];
  const store = cfg.store || new Map();
  let refreshes = 0;
  const session = { user: { id: cfg.uid || "u1" }, access_token: "tok", expires_at: Math.floor(Date.now() / 1000) + 3600 };
  const window = {
    NEX_SUPABASE: { url: "https://x.supabase.co", publishableKey: "pk" },
    NexAuth: { getSession: () => session, refresh: async () => { refreshes++; return { ok: true }; } },
  };
  const ctx = {
    window, JSON, Date, Math, Number, String, Promise, Array, Object, encodeURIComponent, Map, Set, AbortSignal: cfg.noAbort ? undefined : AbortSignal, Finite: 0,
    crypto: { randomUUID: () => "11111111-2222-3333-4444-555555555555" },
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    fetch: async (url, opts) => {
      const body = opts.body ? JSON.parse(opts.body) : undefined;
      calls.push({ url, method: opts.method, headers: opts.headers, body });
      const r = handler(url, opts, body);
      return { ok: r.status < 400, status: r.status, headers: { get: (n) => (n === "Date" && cfg.date ? cfg.date : null) }, json: async () => r.body };
    },
  };
  vm.runInNewContext(src, ctx);
  return { sync: window.NexSync, calls, store, refreshes: () => refreshes };
}

const dash = {
  platform: "macos", dry_run: false, threats_detected: 3, quarantined: 2, canaries_intact: 1,
  daemon: { online: true, version: "0.3.0" },
  toggles: { known_bad_enabled: true, zip_bomb_enabled: true, bin_ai_enabled: true, process_guard_enabled: false, canary_enabled: true },
  known_bad: { loaded: true, entries: 21, created: "2026-11-24T00:00:00+00:00" },
  canaries: [{ path: "/Users/me/secret.docx", state: "Intact" }, { path: "/x", state: "Modified" }],
  watched_dirs: ["/Users/me/Downloads"], data_dir: "/secret",
};
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r)); }; // lets start()'s heartbeat + stuck-command cleanup finish
const fresh = () => new Date().toISOString();

(async () => {
  // name sanitisation
  const { sync } = env(() => ({ status: 200, body: [] }));
  check("name trims and strips control chars", sync.sanitizeName("  Lap\u0000top\n 1 ") === "Lap top 1");
  check("empty name rejected", sync.sanitizeName(" \t\n") === null);
  check("name strips bidi and zero-width chars", sync.sanitizeName("a\u202Eb\u200Bc\uFEFFd\u2066e") === "abcde");
  check("name capped at 60", sync.sanitizeName("a".repeat(100)).length === 60);
  { const n = sync.sanitizeName("a".repeat(59) + "\u{1F600}\u{1F600}"); check("name cut by code points, no lone surrogate", Array.from(n).length === 60 && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(n)); }

  // heartbeat payload
  {
    const e = env((u) => ({ status: u.includes("device_commands") ? 200 : 201, body: [] }));
    e.sync.start(async (c) => (c === "get_dashboard_state" ? dash : null));
    await e.sync.heartbeat();
    const hb = e.calls.find((c) => c.method === "POST" && c.url.endsWith("/rest/v1/devices"));
    const keys = Object.keys(hb.body).sort().join(",");
    check("heartbeat keys are the allowed ones", keys === "app_version,id,last_seen,name,platform,status", keys);
    check("heartbeat status keys", Object.keys(hb.body.status).sort().join(",") === "canaries_intact,canaries_total,dry_run,engines_on,engines_total,online,quarantined,threats_detected");
    check("engines_on counts toggles", hb.body.status.engines_on === 4 && hb.body.status.engines_total === 5 && hb.body.status.canaries_total === 2);
    check("heartbeat has no paths", !/\/Users|\/secret|Downloads/.test(JSON.stringify(hb.body)));
    check("heartbeat upserts with merge-duplicates", hb.headers.Prefer.startsWith("resolution=merge-duplicates") && hb.headers.apikey === "pk" && hb.headers.Authorization === "Bearer tok");
    check("default name from platform", hb.body.name === "macOS device", hb.body.name);
    e.sync.stop();
  }
  {
    // the list engine only counts as on when the service has a list loaded (older services report none)
    const e = env((u) => ({ status: u.includes("device_commands") ? 200 : 201, body: [] }));
    e.sync.start(async (c) => (c === "get_dashboard_state" ? { ...dash, known_bad: undefined } : null));
    await e.sync.heartbeat();
    const hb = e.calls.find((c) => c.method === "POST" && c.url.endsWith("/rest/v1/devices"));
    check("engines_on leaves out a list engine with no list", hb.body.status.engines_on === 3 && hb.body.status.engines_total === 5, hb.body.status.engines_on);
    e.sync.stop();
  }

  // claim skipped when PATCH returns []
  {
    let ran = 0;
    const cmd = { id: "c1", command: "quick_scan", created_at: fresh() };
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: [cmd] } : { status: 200, body: [] }));
    e.sync.start(async () => { ran++; return dash; });
    await settle(); ran = 0; e.calls.length = 0;
    await e.sync.pollOnce();
    check("lost claim race -> not executed", ran === 0);
    check("lost claim race -> no result patch", e.calls.filter((c) => c.method === "PATCH").length === 1);
    e.sync.stop();
  }

  // successful run: only allowlisted commands execute
  {
    const cmds = [
      { id: "a", command: "quick_scan", created_at: fresh() },
      { id: "b", command: "disable_protection", created_at: fresh() },
      { id: "c", command: "verify_canaries", created_at: fresh() },
    ];
    const invoked = [];
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: cmds } : { status: 200, body: [{ id: "x" }] }));
    e.sync.start(async (c) => {
      invoked.push(c);
      if (c === "run_quick_scan") return { findings: [{}], files_scanned: 10, duration_ms: 5 };
      if (c === "verify_canaries") return dash.canaries;
      return dash;
    });
    await settle(); invoked.length = 0; e.calls.length = 0;
    await e.sync.pollOnce();
    check("only allowlisted commands invoked", invoked.join() === "run_quick_scan,verify_canaries", invoked.join());
    const p = e.calls.filter((c) => c.method === "PATCH");
    const unsupported = p.find((c) => c.url.includes("id=eq.b"));
    check("unsupported command marked failed", unsupported.body.status === "failed" && unsupported.body.result.error === "unsupported");
    const scan = p.find((c) => c.url.includes("id=eq.a") && c.body.status === "done");
    check("scan result summary", JSON.stringify(scan.body.result) === '{"threats":1,"files_scanned":10,"duration_ms":5,"blocked":0}');
    const ver = p.find((c) => c.url.includes("id=eq.c") && c.body.status === "done");
    check("canary result summary", JSON.stringify(ver.body.result) === '{"intact":1,"total":2}');
    e.sync.stop();
  }

  // expiry
  {
    let ran = 0;
    const old = { id: "o", command: "quick_scan", created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString() };
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: [old] } : { status: 200, body: [{}] }));
    e.sync.start(async () => { ran++; return dash; });
    await settle(); ran = 0; e.calls.length = 0;
    await e.sync.pollOnce();
    const p = e.calls.filter((c) => c.method === "PATCH");
    check("old command marked expired, not run", ran === 0 && p.length === 1 && p[0].body.status === "expired");
    e.sync.stop();
  }

  // device record is per account; stuck `running` commands are retired on start
  {
    const store = new Map();
    const ids = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"];
    const mk = (uid) => { const e = env((u, o) => ({ status: 200, body: [] }), { store, uid }); e.sync.start(async () => dash); return e; };
    const a = mk("userA");
    const first = a.sync.thisDeviceId();
    a.sync.stop();
    check("device saved under thenex.device.<user id>", store.has("thenex.device.userA") && !store.has("thenex.device"));
    store.set("thenex.device.userB", JSON.stringify({ id: ids[1], name: "B box" }));
    const b = mk("userB");
    check("another user gets its own device record", b.sync.thisDeviceId() === ids[1] && first !== ids[1]);
    b.sync.stop();
    const a2 = mk("userA");
    check("same user reuses its device id", a2.sync.thisDeviceId() === first);
    await new Promise((r) => setImmediate(r)); await new Promise((r) => setImmediate(r));
    const p = a2.calls.find((c) => c.method === "PATCH" && c.url.includes("status=eq.running"));
    check("stuck running commands expired on start (this device only)", p && p.url.includes("device_id=eq." + first) && p.body.status === "expired", p && p.url);
    a2.sync.stop();
  }

  // command age uses the server Date header, not the local clock
  {
    const cmd = { id: "s", command: "quick_scan", created_at: fresh() };
    const date = new Date(Date.now() + 11 * 60 * 1000).toUTCString(); // server says it is 11 min later
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: [cmd] } : { status: 200, body: [{}] }), { date });
    let ran = 0;
    e.sync.start(async () => { ran++; return dash; });
    await settle(); ran = 0; e.calls.length = 0;
    await e.sync.pollOnce();
    const p = e.calls.filter((c) => c.method === "PATCH");
    check("age measured against server time", ran === 0 && p.length === 1 && p[0].body.status === "expired");
    e.sync.stop();
  }

  // remote runs pass {remote:true}; open commands come from their own query
  {
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: u.includes("select=device_id") ? [{ device_id: "d1" }, { device_id: "d1" }] : [{ id: "z", command: "verify_canaries", created_at: fresh() }] } : { status: 200, body: [{}] }));
    const seen = [];
    e.sync.start(async (c, a) => { seen.push([c, a]); return c === "verify_canaries" ? [] : dash; });
    await settle(); seen.length = 0;
    await e.sync.pollOnce();
    check("remote command called with {remote:true}", seen.length === 1 && seen[0][0] === "verify_canaries" && seen[0][1] && seen[0][1].remote === true);
    const l = await e.sync.listDevices();
    const q = e.calls.find((c) => c.url.includes("select=device_id"));
    check("open commands queried by status=in.(pending,running)", q && q.url.includes("status=in.(pending,running)") && l.open.join() === "d1", q && q.url);
    e.sync.stop();
  }

  // remove: never self, DELETE by id, server error surfaced
  {
    const e = env((u, o) => (o.method === "DELETE" ? { status: 400, body: { message: "nope" } } : { status: 200, body: [] }));
    e.sync.start(async () => dash);
    const self = await e.sync.removeDevice(e.sync.thisDeviceId());
    const r = await e.sync.removeDevice("other-id");
    const del = e.calls.find((c) => c.method === "DELETE");
    check("remove refuses this device", !self.ok && !e.calls.some((c) => c.method === "DELETE" && c.url.includes(e.sync.thisDeviceId())));
    check("remove sends DELETE devices?id=eq.<id> and surfaces the error", del.url.endsWith("/rest/v1/devices?id=eq.other-id") && !r.ok && r.error === "nope");
    e.sync.stop();
  }

  // 401 -> one refresh, then stop
  {
    const e = env(() => ({ status: 401, body: { message: "JWT expired" } }));
    const r = await e.sync.sendCommand("d9", "quick_scan");
    check("401 gives up quietly", !r.ok);
    check("401 retried exactly once", e.calls.length === 2 && e.refreshes() === 1, `requests=${e.calls.length} refreshes=${e.refreshes()}`);

  }

  // trigger errors and throttle
  {
    const e = env(() => ({ status: 400, body: { message: "Too many pending commands for this device." } }));
    e.sync.start(async () => dash);
    const r = await e.sync.sendCommand("d1", "quick_scan");
    check("server rate-limit text surfaced", !r.ok && /Too many pending/.test(r.error));
    const r2 = await e.sync.sendCommand("d1", "quick_scan");
    check("client throttle: 2nd click within 1s rejected", !r2.ok && /one request per second/.test(r2.error));
    const r3 = await e.sync.sendCommand("d2", "disable_protection");
    check("non-allowlisted command refused client-side", !r3.ok);
    e.sync.stop();
  }

  // works without AbortSignal.timeout (older WebKit)
  {
    const e = env(() => ({ status: 200, body: [] }), { noAbort: true });
    e.sync.start(async () => dash); await settle();
    check("requests still sent when AbortSignal is missing", e.calls.length > 0);
    e.sync.stop();
  }

  // failed command keeps the backend reason
  {
    const cmd = { id: "f", command: "quick_scan", created_at: fresh() };
    const e = env((u, o) => (o.method === "GET" ? { status: 200, body: [cmd] } : { status: 200, body: [{}] }));
    let boom = false;
    e.sync.start(async () => { if (boom) throw new Error("Needs local approval: open The Nex on this computer"); return dash; });
    await settle(); boom = true; e.calls.length = 0;
    await e.sync.pollOnce();
    const f = e.calls.find((c) => c.method === "PATCH" && c.body.status === "failed");
    check("failed command reports the error reason", f && f.body.result.error === "Needs local approval: open The Nex on this computer", f && JSON.stringify(f.body));
    e.sync.stop();
  }

  // online/ago use server time; open-commands query is windowed
  {
    const date = new Date(Date.now() + 11 * 60 * 1000).toUTCString();
    const e = env(() => ({ status: 200, body: [] }), { date });
    e.sync.start(async () => dash); await settle();
    const srv = Date.now() + 11 * 60 * 1000;
    check("isOnline uses server time", e.sync.isOnline(new Date(srv).toISOString()) === true && e.sync.isOnline(new Date(Date.now()).toISOString()) === false);
    await e.sync.listDevices();
    const q = e.calls.find((c) => c.url.includes("select=device_id"));
    const m = q && /created_at=gt\.([^&]+)/.exec(q.url);
    const t = m && Date.parse(decodeURIComponent(m[1]));
    check("open-commands query has a server-time TTL window", t && Math.abs(t - (srv - 10 * 60 * 1000)) < 5000, q && q.url);
    e.sync.stop();
  }

  console.log(failures ? `\n${failures} failure(s)` : "\nAll sync tests passed");
  process.exit(failures ? 1 : 0);
})();
