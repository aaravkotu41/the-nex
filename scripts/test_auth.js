#!/usr/bin/env node
// Tests for ui/auth.js (Supabase GoTrue client) in a vm with fake fetch/localStorage/timers.
// Run: node scripts/test_auth.js  (exit 1 on failure)
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const src = fs.readFileSync(path.join(__dirname, "..", "ui", "auth.js"), "utf8");

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures++;
}

function env(config, responses, noAbort) {
  const store = new Map();
  const calls = [];
  const timers = [];
  const window = { NEX_SUPABASE: config };
  const ctx = {
    window, URL, JSON, Date, Math, Number, String, Promise, AbortSignal: noAbort ? undefined : AbortSignal,
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    },
    setTimeout: (fn, ms) => timers.push({ fn, ms }),
    clearTimeout: () => {},
    fetch: async (url, opts) => {
      calls.push({ url, opts, body: JSON.parse(opts.body) });
      const r = responses.shift();
      if (r === "offline") throw new TypeError("fetch failed");
      return { ok: r.status < 400, status: r.status, json: async () => r.body };
    },
  };
  vm.runInNewContext(src, ctx);
  return { auth: window.NexAuth, store, calls, timers };
}

const CFG = { url: "https://abc.supabase.co/", publishableKey: "sb_publishable_x" };
const now = () => Math.floor(Date.now() / 1000);
const tokens = (extra) => ({ access_token: "A", refresh_token: "R", expires_in: 3600, user: { id: "u1", email: "a@b.co" }, ...extra });

(async () => {
  let e = env({ url: "", publishableKey: "" }, []);
  check("empty config is not configured", e.auth.isConfigured() === false);
  check("http url is not configured", env({ url: "http://x.co", publishableKey: "k" }, []).auth.isConfigured() === false);
  let r = await e.auth.signIn("a@b.co", "pw");
  check("sign-in refused when not configured", !r.ok && /isn't set up/.test(r.error) && e.calls.length === 0);
  check("restore is null when not configured", (await e.auth.restore()) === null);

  e = env(CFG, [{ status: 200, body: tokens() }]);
  r = await e.auth.signIn("a@b.co", "hunter2-secret");
  const stored = e.store.get("thenex.session") || "";
  const call = e.calls[0];
  check("sign-in succeeds", r.ok && r.session.user.email === "a@b.co");
  check("sign-in hits password grant with apikey", call.url === "https://abc.supabase.co/auth/v1/token?grant_type=password" && call.opts.headers.apikey === CFG.publishableKey, call.url);
  check("session stored with only allowed keys", Object.keys(JSON.parse(stored)).sort().join() === "access_token,expires_at,refresh_token,user");
  check("password never stored", !stored.includes("hunter2") && ![...e.store.values()].some((v) => v.includes("hunter2")));
  check("refresh timer scheduled ~60 s before expiry", e.timers.length === 1 && e.timers[0].ms > 3400 * 1000 && e.timers[0].ms <= 3540 * 1000, String(e.timers[0] && e.timers[0].ms));

  e = env(CFG, [{ status: 400, body: { error_description: "Invalid login credentials" } }]);
  r = await e.auth.signIn("a@b.co", "bad");
  check("bad credentials mapped", !r.ok && r.error === "Incorrect email or password." && !e.store.has("thenex.session"), r.error);
  e = env(CFG, ["offline"]);
  r = await e.auth.signIn("a@b.co", "pw");
  check("offline mapped", !r.ok && /Can't reach the sign-in service/.test(r.error), r.error);
  e = env(CFG, [{ status: 422, body: { msg: "User already registered" } }]);
  r = await e.auth.signUp("a@b.co", "pw");
  check("msg field mapped", !r.ok && /already exists/.test(r.error), r.error);

  e = env(CFG, [{ status: 200, body: { id: "u1", email: "a@b.co" } }]);
  r = await e.auth.signUp("a@b.co", "pw123456");
  check("sign-up without session asks to confirm email", r.ok && r.needsConfirmation && /Check your inbox/.test(r.message) && !e.store.has("thenex.session"));
  check("sign-up posts to /auth/v1/signup", e.calls[0].url === "https://abc.supabase.co/auth/v1/signup");
  e = env(CFG, [{ status: 200, body: tokens() }]);
  r = await e.auth.signUp("a@b.co", "pw123456");
  check("sign-up with session signs in", r.ok && !r.needsConfirmation && e.store.has("thenex.session"));

  const old = { access_token: "OLD", refresh_token: "R0", expires_at: now() - 10, user: { id: "u1", email: "a@b.co" } };
  e = env(CFG, [{ status: 200, body: tokens({ access_token: "NEW", refresh_token: "R1" }) }]);
  e.store.set("thenex.session", JSON.stringify(old));
  let s = await e.auth.restore();
  check("expired session opens at once, before the refresh answers", s && s.access_token === "OLD" && e.auth.getSession() === s);
  await e.auth.refresh(); // the renewal restore() started
  check("expired session uses refresh grant", e.calls.length === 1 && e.calls[0].url.endsWith("grant_type=refresh_token") && e.calls[0].body.refresh_token === "R0" && e.auth.getSession().access_token === "NEW");
  check("refreshed session persisted", JSON.parse(e.store.get("thenex.session")).refresh_token === "R1");

  const fresh = { ...old, expires_at: now() + 3000 };
  e = env(CFG, []);
  e.store.set("thenex.session", JSON.stringify(fresh));
  s = await e.auth.restore();
  check("fresh stored session reused without network", s && s.access_token === "OLD" && e.calls.length === 0);

  e = env(CFG, [{ status: 400, body: { error: "invalid_grant", error_description: "Invalid Refresh Token" } }]);
  e.store.set("thenex.session", JSON.stringify(old));
  let signedOut = 0; e.auth.onSessionLost(() => signedOut++);
  s = await e.auth.restore();
  await e.auth.refresh();
  check("rejected refresh after restore clears the session and signs out", s && !e.store.has("thenex.session") && e.auth.getSession() === null && signedOut === 1 && e.calls.length === 1);

  // refresh: only 400/401 end the session; 429/5xx keep it and report offline
  for (const status of [429, 500, 503]) {
    e = env(CFG, [{ status, body: { msg: "busy" } }]);
    e.store.set("thenex.session", JSON.stringify(old));
    r = await e.auth.refresh();
    check(`refresh ${status} keeps session, offline`, r.offline === true && e.store.has("thenex.session"));
  }
  e = env(CFG, [{ status: 401, body: { msg: "bad" } }]);
  e.store.set("thenex.session", JSON.stringify(old));
  let lost = 0; e.auth.onSessionLost(() => lost++);
  r = await e.auth.refresh();
  check("refresh 401 clears session and calls onLost", !r.ok && !r.offline && !e.store.has("thenex.session") && lost === 1);
  e = env(CFG, ["offline"]);
  e.store.set("thenex.session", JSON.stringify(old));
  r = await e.auth.refresh();
  check("network failure keeps session", r.offline && e.store.has("thenex.session"));
  e = env(CFG, [{ status: 200, body: tokens({ refresh_token: "R2" }) }]);
  e.store.set("thenex.session", JSON.stringify(old));
  await e.auth.refresh();
  check("refresh reads the stored token", e.calls[0].body.refresh_token === "R0");

  // restore while the service is unreachable keeps the stored session
  e = env(CFG, ["offline"]);
  e.store.set("thenex.session", JSON.stringify({ ...old, expires_at: now() + 20 }));
  s = await e.auth.restore();
  check("restore keeps a near-expiry session when refresh is offline", s && s.access_token === "OLD" && e.auth.getSession() === s && e.store.has("thenex.session"));
  check("fetches carry an abort timeout signal", e.calls[0].opts.signal !== undefined);
  { const n = env(CFG, [{ status: 200, body: tokens() }], true); const r = await n.auth.signIn("a@b.co", "pw"); check("sign-in works without AbortSignal.timeout", r && r.ok !== false && n.calls.length === 1 && n.calls[0].opts.signal === undefined); }

  e = env(CFG, [{ status: 200, body: tokens() }, { status: 204, body: null }]);
  await e.auth.signIn("a@b.co", "pw");
  await e.auth.signOut();
  const out = e.calls[1];
  check("sign-out clears storage", !e.store.has("thenex.session") && e.auth.getSession() === null);
  check("sign-out is local-scope only", out.url.endsWith("scope=local"));
  check("sign-out calls logout with bearer token", out.url === "https://abc.supabase.co/auth/v1/logout?scope=local" && out.opts.headers.Authorization === "Bearer A");

  console.log(failures ? `\n${failures} FAILED` : "\nAll auth tests passed");
  process.exit(failures ? 1 : 0);
})();
