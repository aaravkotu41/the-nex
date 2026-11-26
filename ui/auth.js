"use strict";
// Supabase Auth (GoTrue REST) for The Nex: email + password, no SDK. One global: window.NexAuth.
// Pure logic first (testable in a vm, see scripts/test_auth.js); DOM wiring at the bottom.
(function () {
  const KEY = "thenex.session";
  const SKEW = 60; // seconds: treat a session this close to expiry as expired, refresh this early
  let session = null;
  let timer = null;
  let inflight = null;
  let onLost = null;

  const cfg = () => window.NEX_SUPABASE || {};
  function isConfigured() {
    const c = cfg();
    return !!(c.url && c.publishableKey && /^https:\/\//i.test(c.url));
  }
  const now = () => Math.floor(Date.now() / 1000);

  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(KEY) || "null");
      if (s && typeof s.access_token === "string" && typeof s.refresh_token === "string" && Number.isFinite(s.expires_at) && s.user && typeof s.user.email === "string") return s;
    } catch { /* unreadable or storage blocked */ }
    return null;
  }
  function save(s) {
    try { localStorage.setItem(KEY, JSON.stringify(s)); } catch { /* session lasts until the window closes */ }
  }
  let cleared = 0; // a reply that comes after a sign-out must not sign in again
  function clear() {
    cleared += 1;
    session = null;
    if (timer) { clearTimeout(timer); timer = null; }
    try { localStorage.removeItem(KEY); } catch { /* nothing stored */ }
  }

  // Only these fields are ever kept; the password never reaches storage.
  function toSession(body) {
    if (!body || typeof body.access_token !== "string" || typeof body.refresh_token !== "string") return null;
    const expires = Number.isFinite(body.expires_at) ? body.expires_at : now() + (Number(body.expires_in) || 3600);
    const user = body.user || {};
    return { access_token: body.access_token, refresh_token: body.refresh_token, expires_at: expires, user: { id: user.id || "", email: user.email || "" } };
  }

  function friendly(status, body) {
    const raw = String((body && (body.error_description || body.msg || body.message || body.error)) || "").trim();
    const m = raw.toLowerCase();
    if (m.includes("invalid login credentials")) return "Incorrect email or password.";
    if (m.includes("email not confirmed")) return "Confirm your email first, then sign in.";
    if (m.includes("already registered") || m.includes("already been registered")) return "An account with this email already exists. Sign in instead.";
    if (status === 429 || m.includes("rate limit")) return "Too many attempts. Wait a minute and try again.";
    if (m.includes("password should be") || m.includes("weak password")) return raw.replace(/\.?$/, ".");
    if (m.includes("valid email") || m.includes("invalid email")) return "Enter a valid email address.";
    if (raw) return raw.charAt(0).toUpperCase() + raw.slice(1).replace(/\.?$/, ".");
    return "Sign-in failed (HTTP " + status + ").";
  }

  // -> { ok, status, body } or { ok:false, offline:true }
  async function post(path, payload, token) {
    const c = cfg();
    const base = String(c.url).replace(/\/+$/, "") + "/";
    const headers = { apikey: c.publishableKey, "Content-Type": "application/json" };
    if (token) headers.Authorization = "Bearer " + token;
    let res;
    try {
      res = await fetch(new URL(path.replace(/^\//, ""), base).toString(), { method: "POST", headers, body: JSON.stringify(payload || {}), signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined });
    } catch {
      return { ok: false, offline: true };
    }
    let body = null;
    try { body = await res.json(); } catch { /* empty body (logout) */ }
    return { ok: res.ok, status: res.status, body };
  }
  const OFFLINE = "Can't reach the sign-in service. Check your connection.";
  const NOT_SET = "Sign-in isn't set up yet: add your Supabase URL and publishable key to ui/supabase-config.js.";

  function adopt(s) {
    session = s;
    save(s);
    schedule();
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    if (!session) return;
    const wait = Math.max(5000, (session.expires_at - SKEW - now()) * 1000);
    timer = setTimeout(async () => {
      const r = await refresh();
      if (r.offline) timer = setTimeout(schedule, 30000); // keep the session, retry
    }, wait);
  }

  function refresh() {
    if (inflight) return inflight;
    const s = load() || session; // stored copy first: another refresh may have rotated the token
    if (!isConfigured()) return Promise.resolve({ ok: false, error: NOT_SET });
    if (!s) return Promise.resolve({ ok: false, error: "No session." });
    const before = cleared;
    inflight = (async () => {
      const r = await post("auth/v1/token?grant_type=refresh_token", { refresh_token: s.refresh_token });
      if (cleared !== before) return { ok: false, error: "Signed out." };
      if (r.offline) return { ok: false, offline: true, error: OFFLINE };
      const next = r.ok ? toSession(r.body) : null;
      // Only a definitive rejection ends the session; 429/5xx/odd replies keep it and retry later.
      if (!next && r.status !== 400 && r.status !== 401) return { ok: false, offline: true, error: OFFLINE };
      if (!next) { clear(); if (onLost) onLost(); return { ok: false, error: friendly(r.status, r.body) }; }
      adopt(next);
      return { ok: true, session: next };
    })().finally(() => { inflight = null; });
    return inflight;
  }

  // Stored session -> session at once, or null. One that expired while the app was closed is
  // renewed behind the dashboard (which works without the cloud): waiting for that request
  // kept the sign-in screen up for seconds on every launch, as if the user had been signed
  // out. A definite rejection still signs out, through onLost.
  async function restore() {
    if (!isConfigured()) return null;
    const s = load();
    if (!s) return null;
    if (s.expires_at - now() > SKEW) { adopt(s); return s; }
    session = s;
    refresh().then((r) => { if (r.offline) schedule(); }); // unreachable: keep the session, retry
    return s;
  }

  async function signIn(email, password) {
    if (!isConfigured()) return { ok: false, error: NOT_SET };
    const r = await post("auth/v1/token?grant_type=password", { email, password });
    if (r.offline) return { ok: false, error: OFFLINE };
    const s = r.ok ? toSession(r.body) : null;
    if (!s) return { ok: false, error: friendly(r.status, r.body) };
    adopt(s);
    return { ok: true, session: s };
  }

  async function signUp(email, password) {
    if (!isConfigured()) return { ok: false, error: NOT_SET };
    const r = await post("auth/v1/signup", { email, password });
    if (r.offline) return { ok: false, error: OFFLINE };
    if (!r.ok) return { ok: false, error: friendly(r.status, r.body) };
    const s = toSession(r.body);
    if (s) { adopt(s); return { ok: true, session: s }; }
    return { ok: true, needsConfirmation: true, message: "Check your inbox to confirm your email, then sign in." };
  }

  async function signOut() {
    const token = session && session.access_token;
    clear();
    if (token && isConfigured()) await post("auth/v1/logout?scope=local", {}, token); // best effort
  }

  window.NexAuth = {
    isConfigured, restore, refresh, signIn, signUp, signOut, friendlyError: friendly,
    getSession: () => session,
    onSessionLost(fn) { onLost = fn; },
  };

  // ---- DOM wiring: login gate. Calls start() exactly once, after a valid session. ----------
  if (typeof document === "undefined") return;
  const $ = (id) => document.getElementById(id);
  let mode = "signin";

  function show(el, text, tone) {
    el.textContent = text || "";
    el.dataset.tone = tone || "";
  }

  // "jane.doe42@x" -> "Jane Doe": the email's name part, split on . _ - +, digits dropped.
  function nameFromEmail(email) {
    const local = String(email).split("@")[0];
    const words = local.split(/[._+-]+/).map((w) => w.replace(/\d+/g, "")).filter(Boolean);
    const name = words.map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase()).join(" ");
    return name || local;
  }

  // Gravatar photo for the email (sent as a SHA-256 hash); initials stay if there is none.
  async function showAccount(email) {
    const name = nameFromEmail(email);
    $("account-name").textContent = name;
    $("account-name").parentElement.title = email;
    $("account-initials").textContent = name.split(" ").slice(0, 2).map((w) => w[0]).join("").toUpperCase();
    if (!(window.crypto && crypto.subtle)) return;
    try {
      const bytes = new TextEncoder().encode(String(email).trim().toLowerCase());
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
      const img = $("account-photo");
      img.onload = () => { img.hidden = false; };
      img.src = `https://gravatar.com/avatar/${hash}?s=64&d=404`;
    } catch { /* keep the initials */ }
  }
  window.NexAuth.nameFromEmail = nameFromEmail;

  window.NexAuth.gate = async function (start) {
    const form = $("login-form"), msg = $("login-msg"), submit = $("login-submit"), toggle = $("login-toggle");
    const email = $("login-email"), pass = $("login-password"), lock = $("login");
    let started = false;
    const enter = (s) => {
      if (started) return;
      started = true;
      lock.hidden = true;
      document.querySelector(".app").hidden = false;
      const title = $("page-title"); title.tabIndex = -1; title.focus();
      showAccount(s.user.email);
      start();
    };
    $("signout").addEventListener("click", async () => { await signOut(); location.reload(); });

    if (!isConfigured()) {
      show(msg, NOT_SET, "error");
      for (const el of form.elements) el.disabled = true;
      return;
    }
    const setMode = (m) => {
      mode = m;
      const up = m === "signup";
      $("login-title").textContent = up ? "Create account" : "Sign in";
      submit.querySelector(".label").textContent = up ? "Create account" : "Sign in";
      toggle.textContent = up ? "Have an account? Sign in" : "New here? Create account";
      pass.autocomplete = up ? "new-password" : "current-password";
      show(msg, "");
    };
    toggle.addEventListener("click", () => setMode(mode === "signin" ? "signup" : "signin"));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (submit.disabled) return;
      const e1 = email.value.trim(), p1 = pass.value;
      pass.value = "";
      submit.disabled = true; submit.classList.add("busy");
      show(msg, "");
      const r = mode === "signup" ? await signUp(e1, p1) : await signIn(e1, p1);
      submit.disabled = false; submit.classList.remove("busy");
      if (!r.ok) show(msg, r.error, "error");
      else if (r.needsConfirmation) { setMode("signin"); show(msg, r.message, "ok"); }
      else enter(r.session);
    });
    const s = await restore();
    onLost = () => location.reload(); // set after restore: a failed restore just shows the login form
    if (s) enter(s);
    else email.focus();
  };
})();
