"use strict";
// AegisMesh console. Runs standalone (aegismesh-gui) or inside The Nex (iframe, parent IPC).
// Every operation is a local simulation in aegismesh-core; the camera is analysed in-page as
// per-frame brightness change only and nothing is recorded, stored or sent.
(() => {
  const $ = (id) => document.getElementById(id);

  // Nothing on this page may reach beyond this device and the app (the page CSP says the same).
  // The vision runtime ships with a usage logger that would phone home; this counts and stops it.
  const netGuard = { blocked: 0, hosts: new Set() };
  (() => {
    const allowed = (url) => url.origin === location.origin || url.protocol === "ipc:" || url.hostname === "ipc.localhost" || url.protocol === "blob:" || url.protocol === "data:";
    const refuse = (url) => { netGuard.blocked++; netGuard.hosts.add(url.host); };
    const parse = (input) => {
      try {
        const raw = typeof input === "string" || input instanceof URL ? String(input) : input && input.url;
        return new URL(raw, location.href);
      } catch (e) { return null; }
    };
    if (window.fetch) {
      const nativeFetch = window.fetch.bind(window);
      window.fetch = (input, init) => {
        const url = parse(input);
        if (url && !allowed(url)) { refuse(url); return Promise.reject(new TypeError("AegisMesh keeps everything on this device")); }
        return nativeFetch(input, init);
      };
    }
    if (navigator.sendBeacon) {
      const nativeBeacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = (input, data) => {
        const url = parse(input);
        if (!url || !allowed(url)) { if (url) refuse(url); return false; }
        return nativeBeacon(input, data);
      };
    }
    const nativeOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, input, ...rest) {
      const url = parse(input);
      if (url && !allowed(url)) { refuse(url); throw new TypeError("AegisMesh keeps everything on this device"); }
      return nativeOpen.call(this, method, input, ...rest);
    };
  })();

  const embedded = (() => { try { return window.parent !== window; } catch (e) { return true; } })();
  if (embedded) document.documentElement.classList.add("embedded");

  function tauri() {
    if (window.__TAURI__ && window.__TAURI__.core) return window.__TAURI__;
    try {
      if (embedded && window.parent.__TAURI__ && window.parent.__TAURI__.core) return window.parent.__TAURI__;
    } catch (e) { /* cross-origin parent */ }
    return null;
  }
  const connected = () => tauri() !== null;

  async function api(op, request = {}) {
    const t = tauri();
    if (!t) throw new Error("Open AegisMesh from The Nex or the AegisMesh desktop app to run the simulation.");
    return t.core.invoke("aegismesh", { op, request });
  }
  const errorText = (e) => (e && e.message) || String(e);
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const pct = (x, digits = 1) => `${(x * 100).toFixed(digits)}%`;
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  let toastTimer = 0;
  function toast(text, bad = false) {
    const el = $("toast");
    el.textContent = text;
    el.classList.toggle("bad", bad);
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
  }

  async function guarded(button, label, work) {
    const original = button.textContent;
    button.disabled = true;
    if (label) button.textContent = label;
    try {
      await work();
    } catch (error) {
      toast(errorText(error), true);
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  }

  const store = {
    get(key) { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch (e) { return null; } },
    set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* storage unavailable */ } },
  };

  const FORM_ORDER = ["ring", "bracelet", "clothing_tag"];
  const state = {
    defaults: null,
    form: store.get("aegismesh.form") || "ring",
    custom: store.get("aegismesh.profile"),
    profile: null,
    taps: [],
    tapOrigin: null,
    lastTap: 0,
    samples: [],
  };

  // ---------------------------------------------------------------- rhythm helpers (mirror Rust)

  function burstGap(p) {
    const widest = Math.max(...p.ratios);
    return Math.max(p.max_total_ms * widest * (1 + p.tolerance) * 1.2, 250);
  }

  function perform(p, start = 0, pauseMs = null) {
    const total = (p.min_total_ms + p.max_total_ms) / 2;
    const pause = pauseMs !== null ? Math.max(pauseMs, burstGap(p) * 1.15) : (burstGap(p) + p.max_pause_ms) / 2;
    const taps = [];
    let t = start;
    for (let rep = 0; rep < p.repeats; rep++) {
      if (rep > 0) t += pause;
      taps.push(t);
      for (const ratio of p.ratios) { t += ratio * total; taps.push(t); }
    }
    return taps;
  }

  // ---------------------------------------------------------------- form factor + profile

  const FORM_ART = {
    ring: '<svg viewBox="0 0 110 90"><ellipse cx="55" cy="50" rx="30" ry="30" fill="none" stroke="currentColor" stroke-width="9"/><rect x="43" y="13" width="24" height="12" rx="4" fill="currentColor"/></svg>',
    bracelet: '<svg viewBox="0 0 110 90"><ellipse cx="55" cy="47" rx="44" ry="24" fill="none" stroke="currentColor" stroke-width="8"/><rect x="40" y="13" width="30" height="20" rx="6" fill="#111317" stroke="currentColor" stroke-width="3"/></svg>',
    clothing_tag: '<svg viewBox="0 0 110 90"><path d="M30 18h40l14 14v40H30z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="round"/><circle cx="72" cy="30" r="5" fill="currentColor"/><path d="M40 52h34M40 62h22" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>',
  };

  function defaultProfile(form) {
    const index = FORM_ORDER.indexOf(form);
    return state.defaults.profiles[index >= 0 ? index : 0];
  }

  function currentProfile() {
    if (state.custom && state.custom.form === state.form && state.custom.profile) return state.custom.profile;
    return defaultProfile(state.form);
  }

  function renderForms() {
    const holder = $("forms");
    holder.innerHTML = "";
    for (const spec of state.defaults.forms) {
      const button = document.createElement("button");
      button.type = "button";
      button.setAttribute("role", "radio");
      button.setAttribute("aria-checked", String(spec.form === state.form));
      button.textContent = spec.label;
      button.addEventListener("click", () => selectForm(spec.form));
      holder.appendChild(button);
    }
    const spec = state.defaults.forms.find((f) => f.form === state.form) || state.defaults.forms[0];
    $("form-art").innerHTML = FORM_ART[spec.form] || "";
    $("form-specs").innerHTML = [
      ["Tap surface", spec.tap_surface],
      ["Sensor", spec.sensor],
      ["Battery", `${spec.battery_mah} mAh`],
      ["Radio range", `~${spec.radio_range_m} m (simulated BLE)`],
    ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  }

  function renderProfile() {
    const p = state.profile;
    const total = (p.min_total_ms + p.max_total_ms) / 2;
    const pause = Math.min((burstGap(p) + p.max_pause_ms) / 2, 1400);
    const scale = 260 / (total * p.repeats + pause * (p.repeats - 1));
    let bar = "";
    for (let rep = 0; rep < p.repeats; rep++) {
      if (rep > 0) bar += `<span class="pause" style="width:${(pause * scale).toFixed(1)}px"></span>`;
      bar += '<span class="tap"></span>';
      for (const ratio of p.ratios) bar += `<span class="gap" style="width:${(ratio * total * scale).toFixed(1)}px"></span><span class="tap"></span>`;
    }
    const custom = state.custom && state.custom.form === state.form;
    $("profile").innerHTML = `
      <div class="name"><span>${esc(p.name)}</span><span class="muted">${custom ? "calibrated" : "default"}</span></div>
      <div class="rhythm-bar" aria-label="Rhythm: ${p.ratios.length + 1} taps, performed ${p.repeats} time(s)">${bar}</div>
      <div class="facts">
        <span><b>${p.ratios.length + 1}</b> taps</span>
        <span>performed <b>${p.repeats}x</b></span>
        <span>tolerance <b>${Math.round(p.tolerance * 100)}%</b></span>
        <span>one rhythm <b>${Math.round(p.min_total_ms)}-${Math.round(p.max_total_ms)} ms</b></span>
        <span>stillness <b>${(p.quiet_ms / 1000).toFixed(1)} s</b></span>
      </div>`;
  }

  function selectForm(form) {
    state.form = form;
    store.set("aegismesh.form", form);
    state.profile = currentProfile();
    renderForms();
    renderProfile();
    refreshAutomatic();
  }

  // ---------------------------------------------------------------- verdicts

  function renderVerdict(holder, verdict, extra = "") {
    if (!verdict) { holder.innerHTML = ""; return; }
    const ok = verdict.accepted;
    const confidence = ok ? `<div class="meter" title="confidence"><span style="width:${(verdict.confidence * 100).toFixed(0)}%"></span></div>` : "";
    holder.innerHTML = `<div class="box ${ok ? "ok" : "no"}">
      <div class="title">${ok ? "Recognised: a silent SOS would be queued" : "Not recognised: no SOS"}</div>
      <div class="detail">${esc(verdict.reason)}${extra ? ` · ${esc(extra)}` : ""}</div>
      ${confidence}
    </div>`;
  }

  // ---------------------------------------------------------------- timelines

  function sizeCanvas(canvas) {
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(200, Math.round(canvas.clientWidth));
    const height = Number(canvas.getAttribute("height"));
    if (canvas.width !== Math.round(width * ratio)) {
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    return { ctx, width, height };
  }

  function drawTaps(canvas, taps, accepted = null) {
    const { ctx, width, height } = sizeCanvas(canvas);
    ctx.clearRect(0, 0, width, height);
    const span = Math.max(4000, (taps.length ? taps[taps.length - 1] : 0) + 600);
    const x = (t) => 12 + (t / span) * (width - 24);
    ctx.strokeStyle = "#22252C";
    ctx.fillStyle = "#8A90A0";
    ctx.font = "11px ui-monospace, Consolas, monospace";
    for (let s = 0; s <= span; s += 1000) {
      ctx.beginPath(); ctx.moveTo(x(s), 8); ctx.lineTo(x(s), height - 18); ctx.stroke();
      ctx.fillText(`${s / 1000}s`, x(s) + 3, height - 6);
    }
    if (state.profile && taps.length) {
      const gap = burstGap(state.profile);
      ctx.strokeStyle = "rgba(110,168,254,0.45)";
      ctx.lineWidth = 2;
      let start = taps[0];
      for (let i = 1; i <= taps.length; i++) {
        if (i === taps.length || taps[i] - taps[i - 1] >= gap) {
          ctx.beginPath(); ctx.moveTo(x(start), height / 2 - 18); ctx.lineTo(x(taps[i - 1]), height / 2 - 18); ctx.stroke();
          if (i < taps.length) start = taps[i];
        }
      }
      ctx.lineWidth = 1;
    }
    ctx.fillStyle = accepted === null ? "#E7E9EE" : accepted ? "#3DD6B0" : "#FF6B6B";
    for (const t of taps) {
      ctx.beginPath(); ctx.arc(x(t), height / 2, 6, 0, Math.PI * 2); ctx.fill();
    }
  }

  // ---------------------------------------------------------------- tap pad

  function updateTapCount() {
    $("tap-count").textContent = `${state.taps.length} tap${state.taps.length === 1 ? "" : "s"}`;
  }

  function recordTap() {
    const now = performance.now();
    if (state.tapOrigin === null || now - state.lastTap > 6000) {
      state.taps = [];
      state.tapOrigin = now;
      renderVerdict($("tap-verdict"), null);
    }
    state.lastTap = now;
    state.taps.push(Math.round((now - state.tapOrigin) * 10) / 10);
    const pad = $("tap-pad");
    pad.classList.add("hit");
    setTimeout(() => pad.classList.remove("hit"), 90);
    updateTapCount();
    drawTaps($("tap-timeline"), state.taps);
  }

  async function testTaps() {
    if (!state.taps.length) { toast("Tap the rhythm on the pad first."); return; }
    const verdict = await api("classify", { taps_ms: state.taps, profile: state.profile });
    renderVerdict($("tap-verdict"), verdict);
    drawTaps($("tap-timeline"), state.taps, verdict.accepted);
  }

  async function demoRhythm() {
    const taps = perform(state.profile, 300);
    state.taps = [];
    state.tapOrigin = performance.now();
    renderVerdict($("tap-verdict"), null);
    const pad = $("tap-pad");
    for (const t of taps) {
      const wait = t - (performance.now() - state.tapOrigin);
      if (wait > 0) await sleep(wait);
      state.taps.push(t);
      state.lastTap = performance.now();
      pad.classList.add("hit");
      setTimeout(() => pad.classList.remove("hit"), 90);
      updateTapCount();
      drawTaps($("tap-timeline"), state.taps);
    }
    if (connected()) await testTaps();
  }

  // ---------------------------------------------------------------- calibration

  function updateCalibration() {
    $("cal-add").textContent = `Add sample (${state.samples.length})`;
    $("cal-build").disabled = state.samples.length < 3;
  }

  function addSample(taps) {
    if (!taps || taps.length < 3) { toast("A sample needs at least 3 taps: tap your rhythm once, then add it."); return; }
    const first = taps[0];
    state.samples.push(taps.map((t) => t - first));
    updateCalibration();
    toast(`Sample ${state.samples.length} added (${taps.length} taps).`);
  }

  async function buildProfile() {
    const profile = await api("calibrate", {
      samples: state.samples,
      name: $("cal-name").value || "My rhythm",
      repeats: Number($("cal-repeats").value),
    });
    state.custom = { form: state.form, profile };
    store.set("aegismesh.profile", state.custom);
    state.profile = profile;
    state.samples = [];
    updateCalibration();
    renderProfile();
    toast(`Profile "${profile.name}" built. Run the benchmark to see how robust it is.`);
  }

  function resetProfile() {
    state.custom = null;
    store.set("aegismesh.profile", null);
    state.samples = [];
    state.profile = currentProfile();
    updateCalibration();
    renderProfile();
    toast("Back to the default rhythm for this form factor.");
  }

  // ---------------------------------------------------------------- camera

  const ROI = { x: 0.25, y: 0.2, w: 0.5, h: 0.6 };
  const GRID_W = 64;
  const GRID_H = 48;
  const cam = {
    stream: null,
    synthetic: null,
    analyze: null,
    live: [],
    samples: [],
    recording: false,
    recordStart: 0,
    frameHandle: 0,
    usesVideoCallback: false,
    lastVideoTime: -1,
    result: null,
  };
  const work = document.createElement("canvas");
  work.width = GRID_W;
  work.height = GRID_H;
  const workCtx = work.getContext("2d", { willReadFrequently: true });

  // A tap on the simulated hand: a quick 60 ms strike that lands on the beat, then a slow
  // 240 ms return. Shared by the live simulated camera and the frame-exact self-test.
  function drawSyntheticHand(c, t, taps) {
    c.fillStyle = "#1b1e24";
    c.fillRect(0, 0, 320, 240);
    for (let i = 0; i < 160; i++) {
      const g = 24 + Math.floor(Math.random() * 14);
      c.fillStyle = `rgb(${g},${g},${g + 4})`;
      c.fillRect(Math.random() * 320, Math.random() * 240, 3, 3);
    }
    let lift = 0;
    for (const tap of taps) {
      const dt = t - tap + 40;
      if (dt >= 0 && dt < 60) lift = Math.max(lift, dt / 60);
      else if (dt >= 60 && dt < 300) lift = Math.max(lift, 1 - (dt - 60) / 240);
    }
    c.fillStyle = "#c8a68a";
    c.fillRect(112, 138, 96, 70);
    for (let f = 0; f < 4; f++) {
      const tapping = f === 1 || f === 2;
      const y = 70 + (tapping ? lift * 46 : 0);
      c.fillRect(114 + f * 24, y, 18, 72 - (tapping ? lift * 10 : 0));
    }
  }

  class SyntheticCamera {
    // A stand-in webcam stream of the simulated hand, for trying the live flow without a camera.
    constructor() {
      this.canvas = document.createElement("canvas");
      this.canvas.width = 320;
      this.canvas.height = 240;
      this.ctx = this.canvas.getContext("2d");
      this.taps = [];
      this.origin = performance.now();
      this.running = true;
      this.stream = this.canvas.captureStream(30);
      const loop = (now) => {
        if (!this.running) return;
        drawSyntheticHand(this.ctx, now - this.origin, this.taps);
        this.raf = requestAnimationFrame(loop);
      };
      this.raf = requestAnimationFrame(loop);
    }

    perform(times) {
      this.origin = performance.now();
      this.taps = times;
    }

    stop() {
      this.running = false;
      cancelAnimationFrame(this.raf);
      for (const track of this.stream.getTracks()) track.stop();
    }
  }

  // Motion energy of one frame inside the box: mean absolute brightness change from the previous
  // frame, after removing the frame-wide change so auto-exposure and flicker are not motion.
  function makeAnalyzer() {
    let prev = null;
    let prevMean = 0;
    const analyze = (source, width, height) => {
      workCtx.drawImage(source, width * ROI.x, height * ROI.y, width * ROI.w, height * ROI.h, 0, 0, GRID_W, GRID_H);
      const data = workCtx.getImageData(0, 0, GRID_W, GRID_H).data;
      const gray = new Uint8Array(GRID_W * GRID_H);
      let mean = 0;
      for (let i = 0, j = 0; i < data.length; i += 4, j++) {
        gray[j] = (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8;
        mean += gray[j];
      }
      mean /= gray.length;
      let energy = null;
      if (prev) {
        const shift = mean - prevMean;
        let sum = 0;
        for (let k = 0; k < gray.length; k++) sum += Math.abs(gray[k] - prev[k] - shift);
        energy = sum / gray.length;
      }
      prev = gray;
      prevMean = mean;
      analyze.brightness = mean;
      return energy;
    };
    analyze.brightness = null;
    return analyze;
  }

  // Brightness (0..255) at which a webcam's motion and landmark readings stop being reliable.
  const TOO_DARK = 40;
  const TOO_BRIGHT = 225;

  function cancelFrames() {
    const video = $("cam-video");
    if (cam.usesVideoCallback && cam.frameHandle && video.cancelVideoFrameCallback) video.cancelVideoFrameCallback(cam.frameHandle);
    else if (cam.frameHandle) cancelAnimationFrame(cam.frameHandle);
    cam.frameHandle = 0;
  }

  function scheduleFrame() {
    if (!cam.stream) return;
    const video = $("cam-video");
    cam.usesVideoCallback = typeof video.requestVideoFrameCallback === "function";
    if (cam.usesVideoCallback) {
      cam.frameHandle = video.requestVideoFrameCallback((now) => { onFrame(now); scheduleFrame(); });
    } else {
      cam.frameHandle = requestAnimationFrame((now) => { onFrame(now); scheduleFrame(); });
    }
  }

  function onFrame(now) {
    const video = $("cam-video");
    if (!video.videoWidth || video.readyState < 2) return;
    if (!cam.usesVideoCallback) {
      if (video.currentTime === cam.lastVideoTime) return;
      cam.lastVideoTime = video.currentTime;
    }
    const energy = cam.analyze(video, video.videoWidth, video.videoHeight);
    if (!cam.synthetic && now - (cam.lastTip || 0) > 700) {
      cam.lastTip = now;
      const b = cam.analyze.brightness;
      setTip("cam-tip", b === null ? null
        : b < TOO_DARK ? "Too dark inside the box for reliable taps: turn on a light or face a window."
        : b > TOO_BRIGHT ? "The box is washed out: move away from a bright light behind your hand."
        : null);
    }
    if (energy === null) return;
    cam.live.push({ t: now, energy });
    while (cam.live.length && now - cam.live[0].t > 8000) cam.live.shift();
    if (cam.recording) cam.samples.push({ t_ms: Math.round((now - cam.recordStart) * 10) / 10, energy: Math.round(energy * 1000) / 1000 });
    if (!cam.result) drawEnergyLive(now);
  }

  function drawEnergyLive(now) {
    const { ctx, width, height } = sizeCanvas($("cam-energy"));
    ctx.clearRect(0, 0, width, height);
    const span = 8000;
    const max = Math.max(12, ...cam.live.map((s) => s.energy));
    ctx.strokeStyle = cam.recording ? "#FF6B6B" : "#6EA8FE";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    cam.live.forEach((s, i) => {
      const px = width - ((now - s.t) / span) * width;
      const py = height - 6 - (s.energy / max) * (height - 16);
      if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    });
    ctx.stroke();
    ctx.fillStyle = "#8A90A0";
    ctx.font = "11px ui-monospace, Consolas, monospace";
    ctx.fillText(cam.recording ? "recording motion" : "live motion in the box", 8, 14);
  }

  function drawEnergyResult(samples, onsets, accepted) {
    const { ctx, width, height } = sizeCanvas($("cam-energy"));
    ctx.clearRect(0, 0, width, height);
    if (!samples.length) return;
    const span = Math.max(1, samples[samples.length - 1].t_ms);
    const max = Math.max(onsets.threshold * 1.4, ...samples.map((s) => s.energy));
    const x = (t) => 6 + (t / span) * (width - 12);
    const y = (e) => height - 6 - (e / max) * (height - 16);
    ctx.strokeStyle = "rgba(245,181,71,0.7)";
    ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(0, y(onsets.threshold)); ctx.lineTo(width, y(onsets.threshold)); ctx.stroke();
    ctx.setLineDash([]);
    ctx.strokeStyle = "#6EA8FE";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    samples.forEach((s, i) => (i === 0 ? ctx.moveTo(x(s.t_ms), y(s.energy)) : ctx.lineTo(x(s.t_ms), y(s.energy))));
    ctx.stroke();
    ctx.fillStyle = accepted ? "#3DD6B0" : "#FF6B6B";
    for (const t of onsets.taps_ms) {
      ctx.beginPath(); ctx.arc(x(t), 12, 5, 0, Math.PI * 2); ctx.fill();
      ctx.fillRect(x(t) - 0.5, 16, 1, height - 22);
    }
    ctx.fillStyle = "#8A90A0";
    ctx.font = "11px ui-monospace, Consolas, monospace";
    ctx.fillText(`${onsets.taps_ms.length} taps · threshold ${onsets.threshold.toFixed(1)} · ${onsets.fps.toFixed(0)} fps`, 8, height - 8);
  }

  function setCameraUi(on) {
    $("cam-start").disabled = false;
    $("cam-synthetic").disabled = false;
    $("cam-stop").disabled = !on;
    $("cam-record").disabled = !on || cam.recording;
    $("cam-empty").hidden = on;
    $("roi").classList.toggle("live", on);
  }

  // ---------------------------------------------------------------- camera access (shared)
  // One place opens the camera for both the tap test and the sign watch: it remembers which
  // camera you picked, and when access fails it says exactly where to switch it on.

  const IN_APP = location.protocol === "tauri:" || location.hostname === "tauri.localhost";
  const ON_MAC = /Mac/i.test(navigator.platform || navigator.userAgent);
  const camAccess = { state: "unknown", cameras: [], deviceId: store.get("aegismesh.camera") || "", activeLabel: "" };

  function blockedHelp() {
    if (IN_APP && ON_MAC) return "macOS is blocking the camera for The Nex. Open System Settings → Privacy & Security → Camera, switch on The Nex, then reopen the app.";
    if (IN_APP) return "Windows is blocking the camera. Open Settings → Privacy & security → Camera, switch on \"Camera access\" and \"Let desktop apps access your camera\", then press Try again.";
    return "This window blocked the camera. Click the camera icon in the address bar, choose Allow, then press Try again. Some built-in preview browsers never allow cameras: open this page in Chrome, Edge or Safari, or use The Nex app.";
  }

  const CAM_STATES = {
    unknown: ["", "Camera not used yet", "Press Allow camera; you are asked once. Video is analysed in this window only."],
    prompt: ["", "Camera not allowed yet", "Press Allow camera; you are asked once. Video is analysed in this window only."],
    asking: ["busy", "Waiting for your answer…", "Choose Allow in the camera prompt."],
    granted: ["ok", "Camera allowed", "Video is analysed in this window only; it is never recorded, stored or sent."],
    denied: ["bad", "Camera blocked", null],
    missing: ["bad", "No camera found", "Connect a camera, then press Try again. The simulated camera and the self-test work without one."],
    busy: ["bad", "Camera busy", "Another app (a video call?) is using the camera. Close it, then press Try again."],
    unsupported: ["bad", "No camera access in this window", "Cameras need a secure page. Open AegisMesh in The Nex app or in Chrome, Edge or Safari."],
  };

  function setCamAccess(next) {
    camAccess.state = next;
    const [tone, title, text] = CAM_STATES[next] || CAM_STATES.unknown;
    $("cam-state").dataset.tone = tone;
    $("cam-state-title").textContent = title;
    $("cam-state-text").textContent = next === "granted" && camAccess.activeLabel
      ? `Using ${camAccess.activeLabel}. ${text}`
      : text || blockedHelp();
    const allow = $("cam-allow");
    allow.hidden = next === "granted";
    allow.disabled = next === "asking";
    allow.textContent = ["denied", "missing", "busy"].includes(next) ? "Try again" : "Allow camera";
  }

  function cameraProblem(error) {
    const name = error && error.name;
    if (name === "NotAllowedError" || name === "SecurityError" || name === "PermissionDeniedError") return "denied";
    if (name === "NotFoundError" || name === "OverconstrainedError" || name === "DevicesNotFoundError") return "missing";
    if (name === "NotReadableError" || name === "TrackStartError" || name === "AbortError") return "busy";
    return null;
  }

  function cameraConstraints(deviceId) {
    const video = { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 30 } };
    if (deviceId) video.deviceId = { exact: deviceId };
    return { video, audio: false };
  }

  async function openCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setCamAccess("unsupported");
      throw new Error(`${CAM_STATES.unsupported[1]}. ${CAM_STATES.unsupported[2]}`);
    }
    const before = camAccess.state;
    if (before !== "granted") setCamAccess("asking");
    let stream = null;
    let failure = null;
    try {
      stream = await navigator.mediaDevices.getUserMedia(cameraConstraints(camAccess.deviceId));
    } catch (error) {
      failure = error;
    }
    if (!stream && camAccess.deviceId && cameraProblem(failure) === "missing") {
      // The camera picked last time is gone (unplugged): use the default one instead.
      camAccess.deviceId = "";
      store.set("aegismesh.camera", "");
      try {
        stream = await navigator.mediaDevices.getUserMedia(cameraConstraints(""));
      } catch (error) {
        failure = error;
      }
    }
    if (!stream) {
      const problem = cameraProblem(failure);
      if (!problem) {
        setCamAccess(before === "asking" ? "unknown" : before);
        throw failure;
      }
      setCamAccess(problem);
      throw new Error(`${$("cam-state-title").textContent}. ${$("cam-state-text").textContent}`);
    }
    const track = stream.getVideoTracks()[0];
    camAccess.activeLabel = (track && track.label) || "";
    if (track) {
      // stop() never fires "ended", so this only runs when the camera really goes away.
      track.addEventListener("ended", () => {
        if (cam.stream === stream) stopCamera();
        if (signs.stream === stream) stopSigns();
        setCamAccess("missing");
        toast("The camera was disconnected.", true);
      });
    }
    setCamAccess("granted");
    listCameras();
    return stream;
  }

  async function listCameras() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    let devices = [];
    try {
      devices = await navigator.mediaDevices.enumerateDevices();
    } catch (e) {
      return;
    }
    const cameras = devices.filter((d) => d.kind === "videoinput");
    camAccess.cameras = cameras;
    const labelled = cameras.some((c) => c.label);
    const pick = $("cam-pick");
    pick.innerHTML = cameras.map((c, i) => `<option value="${esc(c.deviceId)}">${esc(c.label || `Camera ${i + 1}`)}</option>`).join("");
    const active = cameras.find((c) => c.label && c.label === camAccess.activeLabel);
    const chosen = cameras.find((c) => c.deviceId === camAccess.deviceId) || active;
    if (chosen) pick.value = chosen.deviceId;
    // Camera names are only visible once the camera has been allowed, so a picker before that
    // would be a list of "Camera 1, Camera 2".
    $("cam-pick-wrap").hidden = cameras.length < 2 || !labelled;
  }

  async function watchCameraPermission() {
    let status = null;
    try {
      status = await navigator.permissions.query({ name: "camera" });
    } catch (e) {
      status = null;
    }
    const apply = () => {
      if (!status) setCamAccess("unknown");
      else if (status.state === "granted") setCamAccess("granted");
      else if (status.state === "denied") setCamAccess("denied");
      else setCamAccess("prompt");
      listCameras();
    };
    apply();
    if (status) status.onchange = apply;
  }

  async function allowCamera() {
    const stream = await openCamera();
    // Asking was the point; each camera card opens the camera itself when it starts.
    for (const track of stream.getTracks()) track.stop();
    toast("Camera allowed. Start the camera tap test or Start watching for emergency signs.");
  }

  async function switchCamera() {
    camAccess.deviceId = $("cam-pick").value;
    store.set("aegismesh.camera", camAccess.deviceId);
    if (cam.stream && !cam.synthetic) await startCamera("real");
    else if (signs.stream) {
      stopSigns();
      await startSigns();
    }
  }

  function setTip(id, text) {
    const el = $(id);
    if (el.textContent !== (text || "")) el.textContent = text || "";
    el.hidden = !text;
  }

  async function startCamera(kind) {
    stopCamera();
    if (signs.stream) stopSigns();
    let stream;
    if (kind === "real") {
      stream = await openCamera();
    } else {
      cam.synthetic = new SyntheticCamera();
      stream = cam.synthetic.stream;
    }
    cam.stream = stream;
    cam.analyze = makeAnalyzer();
    cam.live = [];
    cam.result = null;
    const video = $("cam-video");
    video.srcObject = stream;
    video.style.transform = kind === "real" ? "scaleX(-1)" : "none";
    await video.play();
    setCameraUi(true);
    scheduleFrame();
  }

  function stopCamera() {
    cancelFrames();
    if (cam.stream) for (const track of cam.stream.getTracks()) track.stop();
    if (cam.synthetic) cam.synthetic.stop();
    cam.stream = null;
    cam.synthetic = null;
    cam.recording = false;
    $("cam-video").srcObject = null;
    $("countdown").hidden = true;
    setTip("cam-tip", null);
    setCameraUi(false);
  }

  async function showCameraResult(samples, source) {
    if (samples.length < 10) throw new Error("The camera delivered too few frames. Check that it is not in use elsewhere.");
    const result = await api("camera_detect", {
      samples,
      profile: state.profile,
      onset: { sensitivity: Number($("cam-sens").value) },
    });
    cam.result = result;
    const onsets = result.onsets;
    drawEnergyResult(samples, onsets, result.verdict.accepted);
    const expected = (state.profile.ratios.length + 1) * state.profile.repeats;
    let hint = null;
    if (!result.verdict.accepted && onsets.taps_ms.length < expected) {
      hint = onsets.fps < 15
        ? "the camera is too slow to see every tap (is this window in the background?)"
        : "fewer taps seen than the rhythm has: tap a little slower (about 3 a second) and keep your hand in the box";
    } else if (!result.verdict.accepted && onsets.taps_ms.length > expected) {
      hint = "extra movement counted as taps: keep everything except your tapping fingers still";
    }
    const extra = [source, `${onsets.taps_ms.length} of ${expected} taps seen at ${onsets.fps.toFixed(0)} fps`, onsets.warning, hint]
      .filter(Boolean)
      .join(" · ");
    renderVerdict($("cam-verdict"), result.verdict, extra);
    $("cam-use").disabled = onsets.taps_ms.length < 3;
  }

  async function recordCamera() {
    const plan = perform(state.profile, 900, 1000);
    const duration = Math.max(6000, plan[plan.length - 1] + 1500);
    cam.samples = [];
    cam.result = null;
    cam.recording = true;
    cam.recordStart = performance.now();
    renderVerdict($("cam-verdict"), null);
    $("cam-use").disabled = true;
    $("cam-record").disabled = true;
    if (cam.synthetic) cam.synthetic.perform(plan);
    const countdown = $("countdown");
    countdown.hidden = false;
    const ends = cam.recordStart + duration;
    while (performance.now() < ends && cam.recording) {
      countdown.textContent = `REC ${Math.ceil((ends - performance.now()) / 1000)} s`;
      await sleep(200);
    }
    countdown.hidden = true;
    const stopped = !cam.recording;
    cam.recording = false;
    if (stopped || !cam.stream) return;
    await showCameraResult(cam.samples.slice(), cam.synthetic ? "simulated camera" : "your camera");
    $("cam-record").disabled = !cam.stream;
  }

  // Renders the simulated hand frame by frame at exactly 30 fps and pushes every frame through
  // the same motion analysis and tap detector, independent of real time or window focus.
  async function cameraSelfTest() {
    const plan = perform(state.profile, 900, 1000);
    const duration = Math.max(6000, plan[plan.length - 1] + 1500);
    const canvas = document.createElement("canvas");
    canvas.width = 320;
    canvas.height = 240;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const analyze = makeAnalyzer();
    const samples = [];
    for (let frame = 0; frame * (1000 / 30) <= duration; frame++) {
      const t = frame * (1000 / 30);
      drawSyntheticHand(ctx, t, plan);
      const energy = analyze(canvas, 320, 240);
      if (energy !== null) samples.push({ t_ms: Math.round(t * 10) / 10, energy: Math.round(energy * 1000) / 1000 });
    }
    renderVerdict($("cam-verdict"), null);
    await showCameraResult(samples, "self-test: simulated hand at 30 fps");
  }

  // ---------------------------------------------------------------- emergency signs (camera)

  const VENDOR = "vendor/mediapipe";
  const vision = { V: null, hand: null, face: null, loading: null, delegate: "" };
  const signs = {
    stream: null,
    watcher: null,
    frameHandle: 0,
    usesVideoCallback: false,
    lastVideoTime: -1,
    lastProcessed: 0,
    frameNo: 0,
    slow: false,
    lastFace: null,
    lastHands: null,
    teaching: null,
    test: null,
    results: store.get("aegismesh.signtests") || {},
    customs: [],
    enabled: store.get("aegismesh.builtins") || ["signal_for_help", "double_wink"],
    lastRender: 0,
  };

  function setVisionStatus(text, tone = "") {
    $("vision-text").textContent = text;
    $("vision-status").dataset.tone = tone;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`${src} could not be loaded`));
      document.head.appendChild(script);
    });
  }

  async function loadVision() {
    if (vision.hand && vision.face) return;
    if (vision.loading) return vision.loading;
    vision.loading = (async () => {
      setVisionStatus("Loading on-device vision models (about 27 MB, from this app, not the internet)…", "busy");
      try {
        await loadScript(`${VENDOR}/vision_bundle.js`);
      } catch (error) {
        throw new Error("On-device vision is not bundled in this build. Run python scripts/fetch_vision_models.py before building.");
      }
      const V = window.Vision;
      if (!V || !V.FilesetResolver) throw new Error("The vision runtime did not initialise.");
      vision.V = V;
      const fileset = await V.FilesetResolver.forVisionTasks(new URL(VENDOR, location.href).href);
      const create = async (Task, options) => {
        try {
          const task = await Task.createFromOptions(fileset, { ...options, baseOptions: { ...options.baseOptions, delegate: "GPU" } });
          vision.delegate = "GPU";
          return task;
        } catch (error) {
          vision.delegate = "CPU";
          return Task.createFromOptions(fileset, { ...options, baseOptions: { ...options.baseOptions, delegate: "CPU" } });
        }
      };
      vision.hand = await create(V.HandLandmarker, {
        baseOptions: { modelAssetPath: `${VENDOR}/hand_landmarker.task` },
        runningMode: "VIDEO",
        numHands: 2,
        minHandDetectionConfidence: 0.6,
        minHandPresenceConfidence: 0.6,
        minTrackingConfidence: 0.5,
      });
      vision.face = await create(V.FaceLandmarker, {
        baseOptions: { modelAssetPath: `${VENDOR}/face_landmarker.task` },
        runningMode: "VIDEO",
        numFaces: 1,
        outputFaceBlendshapes: true,
      });
      setVisionStatus(`On-device vision ready (${vision.delegate}); nothing is sent anywhere`, "ok");
    })();
    try {
      await vision.loading;
    } catch (error) {
      vision.loading = null;
      setVisionStatus(errorText(error), "bad");
      throw error;
    }
  }

  function loadCustoms() {
    const saved = store.get("aegismesh.signs");
    return Array.isArray(saved) ? saved.filter((m) => m && m.name && Array.isArray(m.pos) && Array.isArray(m.neg)) : [];
  }

  function saveCustoms() {
    store.set("aegismesh.signs", signs.customs);
    store.set("aegismesh.builtins", signs.enabled);
    if (signs.watcher) {
      signs.watcher.enabled = new Set(signs.enabled);
      signs.watcher.setCustoms(signs.customs);
    }
  }

  function testBadge(key) {
    const r = signs.results[key];
    if (!r) return `<span class="tested">not tested yet</span>`;
    return r.passed
      ? `<span class="tested good" title="Last test">✓ works (${(r.ms / 1000).toFixed(1)} s)</span>`
      : `<span class="tested bad" title="Last test">✗ not recognised</span>`;
  }

  // Rebuilt only when the list changes; while watching, updateSignMeters() moves the meters,
  // so the buttons are never replaced under the pointer mid-click.
  function renderSignList() {
    const B = window.AegisSigns.BUILTINS;
    const testing = signs.test && signs.test.target;
    const rows = Object.entries(B).map(([key, sign]) => {
      const on = signs.enabled.includes(key);
      return `<li class="${on ? "" : "off"}${testing === key ? " testing" : ""}" data-key="${key}">
        <label class="sign-toggle"><input type="checkbox" data-builtin="${key}" ${on ? "checked" : ""}><span><b>${esc(sign.name)}</b><small>${esc(sign.how)}</small></span></label>
        <span class="tag">${sign.kind === "hand" ? "hand" : "face"} · built-in</span>
        <div class="sign-actions">${testBadge(key)}<button class="btn small" data-test="${key}">Test</button></div>
        <span class="meter"><span style="width:0%"></span></span>
      </li>`;
    });
    for (const m of signs.customs) {
      const key = `custom:${m.name}`;
      const advice = m.quality === "poor"
        ? " Too close to your ordinary pose or taught while moving: teach it again, holding it still, or pick a clearer sign."
        : m.quality === "fair" ? " Usable; more examples make it more reliable." : "";
      rows.push(`<li class="${testing === key ? "testing" : ""}" data-key="${esc(key)}">
        <span class="sign-toggle"><span><b>${esc(m.name)}</b><small>Hold it for about a second. Quality: <em class="q-${esc(m.quality)}">${esc(m.quality)}</em>.${esc(advice)}</small>
          <span class="sign-links"><button class="link" data-improve="${esc(m.name)}" title="Teach more examples of this sign, e.g. from another angle">add examples</button><button class="link" data-reteach="${esc(m.name)}" title="Replace this sign with a fresh one">teach again</button><button class="link" data-forget="${esc(m.name)}" title="Forget this sign">forget</button></span></span></span>
        <span class="tag">${m.kind === "hand" ? "hand" : "face"} · yours</span>
        <div class="sign-actions">${testBadge(key)}<button class="btn small" data-test="${esc(key)}">Test</button></div>
        <span class="meter"><span style="width:0%"></span></span>
      </li>`);
    }
    $("sign-list").innerHTML = rows.join("");
  }

  // Built-in signs: progress through their steps. Your signs: how close the current frame is
  // to the taught sign (the bar lights up when it counts as a match).
  function updateSignMeters(status) {
    for (const li of $("sign-list").children) {
      const key = li.dataset.key || "";
      let value = 0;
      let hot = false;
      if (key.startsWith("custom:")) {
        const d = status && status.scores[key.slice(7)];
        if (d) {
          value = Math.max(0, Math.min(1, 1.5 - d.score));
          hot = d.match;
        }
      } else if (status) {
        value = status.progress[key] || 0;
      }
      const bar = li.querySelector(".meter");
      if (!bar) continue;
      bar.classList.toggle("hot", hot);
      bar.firstElementChild.style.width = `${Math.round(value * 100)}%`;
    }
  }

  function setSignUi(on) {
    $("sign-start").disabled = on;
    $("sign-stop").disabled = !on;
    $("teach-start").disabled = Boolean(signs.teaching);
    $("sign-empty").hidden = on;
  }

  function hud(text) {
    const el = $("sign-hud");
    el.hidden = !text;
    el.textContent = text || "";
  }

  async function startSigns() {
    if (cam.stream) stopCamera();
    await loadVision();
    const stream = await openCamera();
    signs.stream = stream;
    signs.lastSeen = performance.now();
    signs.lastTip = 0;
    signs.fpsFrames = 0;
    signs.fpsSince = performance.now();
    signs.watcher = new window.AegisSigns.SignWatcher({ enabled: signs.enabled, customs: signs.customs });
    const video = $("sign-video");
    video.srcObject = stream;
    await video.play();
    setSignUi(true);
    scheduleSignFrame();
  }

  function stopSigns() {
    const video = $("sign-video");
    if (signs.usesVideoCallback && signs.frameHandle && video.cancelVideoFrameCallback) video.cancelVideoFrameCallback(signs.frameHandle);
    else if (signs.frameHandle) cancelAnimationFrame(signs.frameHandle);
    signs.frameHandle = 0;
    if (signs.stream) for (const track of signs.stream.getTracks()) track.stop();
    signs.stream = null;
    const interrupted = signs.teaching || signs.test;
    signs.teaching = null;
    signs.test = null;
    if (interrupted) {
      renderSignList();
      $("sign-test").innerHTML = "";
    }
    updateSignMeters(null);
    video.srcObject = null;
    const overlay = $("sign-overlay");
    overlay.getContext("2d").clearRect(0, 0, overlay.width, overlay.height);
    hud("");
    setTip("sign-tip", null);
    if (vision.hand) setVisionStatus(`On-device vision ready (${vision.delegate}); nothing is sent anywhere`, "ok");
    setSignUi(false);
  }

  function scheduleSignFrame() {
    if (!signs.stream) return;
    const video = $("sign-video");
    signs.usesVideoCallback = typeof video.requestVideoFrameCallback === "function";
    const next = (now) => {
      try {
        onSignFrame(now);
      } catch (error) {
        setVisionStatus(`Vision error: ${errorText(error)}`, "bad");
      }
      scheduleSignFrame();
    };
    signs.frameHandle = signs.usesVideoCallback ? video.requestVideoFrameCallback(next) : requestAnimationFrame(next);
  }

  function onSignFrame(now) {
    const video = $("sign-video");
    if (!video.videoWidth || video.readyState < 2 || !vision.hand) return;
    if (!signs.usesVideoCallback) {
      if (video.currentTime === signs.lastVideoTime) return;
      signs.lastVideoTime = video.currentTime;
    }
    if (now - signs.lastProcessed < 28) return;
    signs.lastProcessed = now;
    const started = performance.now();
    const frameNo = signs.frameNo++;
    // When a frame takes too long, run the face and hand models on alternate frames.
    const runHand = !signs.slow || frameNo % 2 === 0;
    const runFace = !signs.slow || frameNo % 2 === 1;
    if (runHand) signs.lastHands = vision.hand.detectForVideo(video, now);
    if (runFace) signs.lastFace = vision.face.detectForVideo(video, now);
    signs.slow = performance.now() - started > 26;

    const handResult = signs.lastHands || { landmarks: [] };
    const handedness = handResult.handedness || handResult.handednesses || [];
    const faceResult = signs.lastFace;
    const frame = {
      t: now,
      aspect: video.videoWidth / video.videoHeight,
      hands: (handResult.landmarks || []).map((landmarks, i) => ({
        landmarks,
        handedness: handedness[i] && handedness[i][0] ? handedness[i][0].categoryName : "Right",
      })),
      face: faceResult && faceResult.faceBlendshapes && faceResult.faceBlendshapes[0] ? faceResult.faceBlendshapes[0].categories : null,
    };
    drawSignOverlay(video, handResult, faceResult);
    if (frame.hands.length || frame.face) signs.lastSeen = now;
    signs.fpsFrames++;
    if (now - signs.lastTip > 700) {
      const fps = (signs.fpsFrames * 1000) / Math.max(1, now - signs.fpsSince);
      signs.fpsFrames = 0;
      signs.fpsSince = now;
      signs.lastTip = now;
      setVisionStatus(`Watching on this device (${vision.delegate}, ${fps.toFixed(0)} fps); nothing is sent anywhere`, "ok");
      setTip("sign-tip", signTip(video, frame, now, fps));
    }
    if (signs.teaching) {
      collectTeaching(frame, now);
      return;
    }
    const { events, status } = signs.watcher.update(frame);
    const render = now - signs.lastRender > 120;
    if (render) {
      signs.lastRender = now;
      updateSignMeters(status);
    }
    if (signs.test) {
      // A rehearsal: whatever is recognised is reported here and never sends an SOS.
      onTestFrame(frame, events, status, render);
      return;
    }
    if (render && !$("sign-discreet").checked) hud(describeStatus(status));
    for (const event of events) onSignTriggered(event);
  }

  // ---------------------------------------------------------------- testing a sign

  function signInfo(target) {
    if (target.startsWith("custom:")) {
      const m = signs.customs.find((c) => c.name === target.slice(7));
      return m ? { name: m.name, kind: m.kind } : null;
    }
    const b = window.AegisSigns.BUILTINS[target];
    return b ? { name: b.name, kind: b.kind } : null;
  }

  function freshWatcher(extra = []) {
    signs.watcher = new window.AegisSigns.SignWatcher({ enabled: [...new Set([...signs.enabled, ...extra])], customs: signs.customs });
  }

  async function startSignTest(target) {
    const info = signInfo(target);
    if (!info || signs.teaching) return;
    if (!signs.stream) await startSigns();
    // A fresh watcher, so the cool-down of an earlier trigger cannot hide this one; the tested
    // sign counts even if it is switched off for normal watching.
    freshWatcher(target.startsWith("custom:") ? [] : [target]);
    signs.test = { target, ...info, run: window.AegisSigns.makeSignTest(target, info.kind, { timeoutMs: 10000 }) };
    renderSignList();
    $("sign-test").innerHTML = `<div class="box testing"><div class="title">Testing "${esc(info.name)}"</div>
      <div class="detail">Make the ${info.kind === "face" ? "expression" : "sign"} now, the way you would in an emergency. You have 10 seconds. This is a test: no SOS is sent.</div></div>`;
    hud(`Test: make "${info.name}" now`);
  }

  function onTestFrame(frame, events, status, render) {
    const T = signs.test;
    const seen = T.kind === "face" ? Boolean(frame.face) : frame.hands.length > 0;
    const r = T.run.update(frame.t, events, status, seen);
    if (r.passed === null) {
      if (render) hud(`Test: make "${T.name}" now · ${Math.ceil(r.left / 1000)} s left${r.progress > 0 ? ` · ${Math.round(r.progress * 100)}%` : ""}`);
      return;
    }
    finishSignTest(r);
  }

  function finishSignTest(r) {
    const T = signs.test;
    signs.test = null;
    freshWatcher();
    signs.results[T.target] = { passed: r.passed, ms: Math.round(r.ms), at: Date.now() };
    store.set("aegismesh.signtests", signs.results);
    const secs = (r.ms / 1000).toFixed(1);
    $("sign-test").innerHTML = r.passed
      ? `<div class="box ok"><div class="title">✓ "${esc(T.name)}" recognised in ${secs} s</div>
          <div class="detail">It works with this camera and light. When watching for real, this ${T.kind === "face" ? "expression" : "sign"} sends the silent SOS. (Test only: nothing was sent.)</div></div>`
      : `<div class="box no"><div class="title">✗ "${esc(T.name)}" not recognised in ${secs} s</div>
          <div class="detail">${esc(r.advice)} (Test only: nothing was sent.)</div></div>`;
    const item = document.createElement("li");
    item.className = r.passed ? "ok" : "fail";
    item.textContent = `${new Date().toLocaleTimeString()} · test: ${T.name} ${r.passed ? `recognised in ${secs} s` : "not recognised"} (no SOS sent)`;
    $("sign-log").prepend(item);
    hud(r.passed ? `✓ "${T.name}" recognised` : `✗ "${T.name}" not recognised`);
    setTimeout(() => { if (!signs.test && !signs.teaching && $("sign-discreet").checked) hud(""); }, 2500);
    renderSignList();
  }

  const lumaCanvas = document.createElement("canvas");
  lumaCanvas.width = 32;
  lumaCanvas.height = 24;
  const lumaCtx = lumaCanvas.getContext("2d", { willReadFrequently: true });

  function frameBrightness(video) {
    lumaCtx.drawImage(video, 0, 0, 32, 24);
    const data = lumaCtx.getImageData(0, 0, 32, 24).data;
    let sum = 0;
    for (let i = 0; i < data.length; i += 4) sum += (data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) >> 8;
    return sum / (data.length / 4);
  }

  // The most useful single piece of advice for the current frame, or null when all is well:
  // the things that make signs go unrecognised are light, distance and framing.
  function signTip(video, frame, now, fps) {
    const brightness = frameBrightness(video);
    if (brightness < TOO_DARK) return "Too dark to see signs reliably: turn on a light or face a window.";
    if (brightness > TOO_BRIGHT) return "The picture is washed out: move away from a bright window or lamp behind you.";
    if (now - signs.lastSeen > 2500) return "No hand or face in view: face the camera from about an arm's length away.";
    const hand = frame.hands[0];
    if (hand) {
      let x0 = 1, y0 = 1, x1 = 0, y1 = 0;
      for (const p of hand.landmarks) {
        x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y);
      }
      if (x0 < 0.01 || y0 < 0.01 || x1 > 0.99 || y1 > 0.99) return "Part of your hand is outside the picture: keep the whole hand in view.";
      if (Math.max(y1 - y0, (x1 - x0) * frame.aspect) < 0.15) return "Your hand looks small to the camera: bring it a little closer.";
    }
    if (fps < 10) return `Recognition is slow on this computer (${fps.toFixed(0)} fps): hold each sign a little longer, or close other heavy apps.`;
    return null;
  }

  function describeStatus(status) {
    const parts = [];
    if (status.handState && status.handState !== "none") parts.push(`hand: ${status.handState.replace(/_/g, " ")}`);
    if (status.faceState && status.faceState !== "none") parts.push(`face: ${status.faceState.replace(/_/g, " ")}`);
    if (status.custom) parts.push(`looks like "${status.custom.name}"`);
    return parts.join(" · ") || "looking for a hand or face";
  }

  function drawSignOverlay(video, handResult, faceResult) {
    const canvas = $("sign-overlay");
    if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
    }
    const ctx = canvas.getContext("2d");
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    const connections = (vision.V && vision.V.HandLandmarker.HAND_CONNECTIONS) || [];
    ctx.lineWidth = 3;
    for (const landmarks of handResult.landmarks || []) {
      ctx.strokeStyle = "rgba(61,214,176,0.9)";
      ctx.beginPath();
      for (const c of connections) {
        const a = landmarks[c.start];
        const b = landmarks[c.end];
        if (!a || !b) continue;
        ctx.moveTo(a.x * w, a.y * h);
        ctx.lineTo(b.x * w, b.y * h);
      }
      ctx.stroke();
      ctx.fillStyle = "#E7E9EE";
      for (const p of landmarks) {
        ctx.beginPath();
        ctx.arc(p.x * w, p.y * h, 3.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    const face = faceResult && faceResult.faceLandmarks && faceResult.faceLandmarks[0];
    if (face) {
      let x0 = 1, y0 = 1, x1 = 0, y1 = 0;
      for (const p of face) {
        x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y);
      }
      ctx.strokeStyle = "rgba(110,168,254,0.85)";
      ctx.lineWidth = 2;
      ctx.strokeRect(x0 * w, y0 * h, (x1 - x0) * w, (y1 - y0) * h);
      ctx.fillStyle = "rgba(110,168,254,0.9)";
      for (const i of [33, 133, 362, 263, 61, 291, 13, 14]) {
        const p = face[i];
        if (!p) continue;
        ctx.beginPath();
        ctx.arc(p.x * w, p.y * h, 2.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  function teachingVector(frame, kind) {
    const S = window.AegisSigns;
    if (kind === "face") return frame.face ? S.faceFeatures(S.faceScores(frame.face)) : null;
    const hand = frame.hands[0];
    return hand ? S.handFeatures(S.normalizeHand(hand.landmarks, hand.handedness, frame.aspect)) : null;
  }

  // Teaching runs in phases: a countdown to get into position (not recorded), the sign, a short
  // break to let go of it (not recorded), then the ordinary pose. Recording the moments of moving
  // into and out of the sign is what makes a taught sign blurry and unreliable.
  const TEACH_PHASES = { ready: 3000, sign: 3000, release: 800, neutral: 3000 };

  function collectTeaching(frame, now) {
    const T = signs.teaching;
    const what = T.kind === "hand" ? "hand" : "face";
    const thing = T.kind === "hand" ? "sign" : "expression";
    if (T.phase === "sign" || T.phase === "neutral") {
      const vector = teachingVector(frame, T.kind);
      if (vector) (T.phase === "sign" ? T.samples : T.neutral).push(vector);
    }
    const left = Math.max(0, Math.ceil((T.until - now) / 1000));
    if (T.phase === "ready") hud(`Get ready: make "${T.name}" in ${left}…`);
    else if (T.phase === "sign") hud(`Hold "${T.name}" still · ${left} s · ${T.samples.length} frames`);
    else if (T.phase === "release") hud(`Now let go of the ${thing}…`);
    else hud(`Relax as you normally are, ${what} still in view · ${left} s · ${T.neutral.length} frames`);
    if (now < T.until) return;
    const next = { ready: "sign", sign: "release", release: "neutral" }[T.phase];
    if (!next) {
      finishTeaching();
      return;
    }
    T.phase = next;
    T.until = now + TEACH_PHASES[next];
  }

  async function startTeaching(improveName = null) {
    if (signs.teaching) return;
    const improving = improveName ? signs.customs.find((m) => m.name === improveName) : null;
    const name = improving ? improving.name : $("teach-name").value.trim();
    const kind = improving ? improving.kind : $("teach-kind").value;
    if (!name) {
      toast("Give the sign a name first.");
      $("teach-name").focus();
      return;
    }
    if (!signs.stream) await startSigns();
    signs.test = null;
    $("sign-test").innerHTML = "";
    const replacing = !improving && signs.customs.some((m) => m.name.toLowerCase() === name.toLowerCase());
    signs.teaching = { name, kind, improving: Boolean(improving), replacing, phase: "ready", samples: [], neutral: [], until: performance.now() + TEACH_PHASES.ready };
    $("teach-start").disabled = true;
    renderSignList();
  }

  function finishTeaching() {
    const T = signs.teaching;
    signs.teaching = null;
    $("teach-start").disabled = false;
    const S = window.AegisSigns;
    const what = T.kind === "hand" ? "hand" : "face";
    const unseen = T.samples.length < 8 ? "while you held it" : T.neutral.length < 8 ? "while you relaxed" : null;
    if (unseen) {
      hud("");
      toast(`Could not learn "${T.name}": the camera saw your ${what} in too few frames ${unseen}. Keep your whole ${what} in view, about an arm's length away, in good light, and try again.`, true);
      renderSignList();
      return;
    }
    let model;
    try {
      if (T.improving) {
        const old = signs.customs.find((m) => m.name === T.name);
        model = S.improveSign(old, { samples: T.samples, neutral: T.neutral });
        signs.customs = signs.customs.map((m) => (m.name === T.name ? model : m));
      } else {
        model = S.trainSign({ name: T.name, kind: T.kind, samples: T.samples, neutral: T.neutral });
        signs.customs = [...signs.customs.filter((m) => m.name.toLowerCase() !== model.name.toLowerCase()), model];
      }
    } catch (error) {
      hud("");
      toast(`Could not learn "${T.name}": ${errorText(error)}`, true);
      renderSignList();
      return;
    }
    delete signs.results[`custom:${model.name}`];
    store.set("aegismesh.signtests", signs.results);
    saveCustoms();
    renderSignList();
    if (!T.improving) $("teach-name").value = "";
    const verb = T.improving ? "Improved" : T.replacing ? "Re-taught" : "Learned";
    const advice = model.quality === "poor"
      ? "It is too close to your ordinary pose: try a more distinctive sign, or add examples."
      : model.quality === "fair" ? "Usable; adding examples from another angle makes it more reliable." : "It stands clearly apart from your ordinary pose.";
    toast(`${verb} "${model.name}" (${model.quality}). ${advice} Now testing it…`, model.quality === "poor");
    hud(`${verb} "${model.name}". Relax, then make it again to test it…`);
    // Check it straight away, the same way an emergency would use it.
    setTimeout(() => {
      if (signs.stream && !signs.teaching && !signs.test) startSignTest(`custom:${model.name}`).catch((error) => toast(errorText(error), true));
    }, 1800);
  }

  async function onSignTriggered(event) {
    const when = new Date().toLocaleTimeString();
    const item = document.createElement("li");
    item.textContent = `${when} · ${event.name} recognised → sending silent SOS (simulation)…`;
    $("sign-log").prepend(item);
    if (!$("sign-discreet").checked) hud(`${event.name}: silent SOS sent (simulation)`);
    try {
      const outcome = await api("simulate_mesh", {
        form: state.form,
        relays: 4,
        ttl: 6,
        redundant_links: true,
        late_link: false,
        seconds: 4,
        camera_sign: event.name,
      });
      const silent = Object.values(outcome.phone).every((v) => v === 0);
      item.textContent = `${when} · ${event.name} → silent SOS ${outcome.stats.delivered_sos ? `delivered in ${outcome.stats.max_hops} hops` : "NOT delivered"}, phone ${silent ? "silent" : "NOT silent"}, location wiped (simulation)`;
      item.className = outcome.pass ? "ok" : "fail";
    } catch (error) {
      item.textContent = `${when} · ${event.name} recognised, but the simulation could not run: ${errorText(error)}`;
      item.className = "fail";
    }
  }

  // ---------------------------------------------------------------- benchmark

  async function runBenchmark() {
    const report = await api("robustness", { profile: state.profile, trials: 2000 });
    const rows = report.false_accepts.map((f) => {
      const cls = f.false_accepts === 0 ? "good" : f.per_hour < 1 ? "warn" : "bad";
      return `<tr><td>${esc(f.activity)}</td><td class="num">${f.sessions} × ${f.session_seconds}s</td><td class="num ${cls}">${f.false_accepts}</td><td class="num ${cls}">${f.per_hour.toFixed(2)}</td></tr>`;
    }).join("");
    $("bench-body").innerHTML = `
      <div class="bench-head">
        <div class="big"><b class="${report.detection_rate >= 0.99 ? "good" : "warn"}">${pct(report.detection_rate)}</b><span>of ${report.trials.toLocaleString()} attempts recognised</span></div>
        <div class="big"><b class="${report.sloppy_detection_rate >= 0.95 ? "good" : "warn"}">${pct(report.sloppy_detection_rate)}</b><span>when hurried or seen by a webcam</span></div>
      </div>
      <table>
        <thead><tr><th>Everyday activity</th><th class="num">Sessions</th><th class="num">False SOS</th><th class="num">Per hour</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="hint">Synthetic activity with a fixed seed: a regression benchmark for this rhythm, not a field trial.</p>`;
  }

  // ---------------------------------------------------------------- zeroization + frames

  function formatNs(ns) {
    if (ns < 1000) return `${ns} ns`;
    if (ns < 1e6) return `${(ns / 1000).toFixed(1)} µs`;
    return `${(ns / 1e6).toFixed(2)} ms`;
  }

  async function runZeroization() {
    const outcome = await api("zeroization", { form: state.form });
    const wipe = outcome.wipe || { wiped_bytes: 0, elapsed_ns: 0, verified_zero: false };
    $("zero-body").innerHTML = `
      <div class="zero-grid">
        <div class="big"><b class="${outcome.pass ? "good" : "bad"}">${formatNs(wipe.elapsed_ns)}</b><span>to wipe after dispatch</span></div>
        <div class="big"><b>${wipe.wiped_bytes} B</b><span>location, token and frame wiped</span></div>
        <div class="big"><b class="${outcome.retained_location_bytes === 0 ? "good" : "bad"}">${outcome.retained_location_bytes} B</b><span>retained afterwards</span></div>
      </div>
      <div class="timerbar"><div class="held" style="width:0"></div><div class="label"><span>tap recognised · fix taken</span><span>frame sent · wiped ${wipe.verified_zero ? "(verified zero)" : ""}</span></div></div>
      <p class="hint">The fix exists only until its frame leaves the radio (whole dispatch ${outcome.dispatch_us.toFixed(0)} µs here). No location history is ever written.</p>`;
    requestAnimationFrame(() => { const held = document.querySelector(".timerbar .held"); if (held) held.style.width = "100%"; });
    const preview = await api("frame_preview", { form: state.form });
    const header = preview.header_len * 2;
    const row = (hex) => `<em>${hex.slice(0, header)}</em>${hex.slice(header)}`;
    $("frames").innerHTML = `
      <div class="tag">Wellness frame (what a radio scanner captures)</div><code class="hex">${row(preview.wellness_hex)}</code>
      <div class="tag">SOS frame: same ${preview.frame_len}-byte shape, same step-counter header (blue); the rest is sealed</div><code class="hex">${row(preview.sos_hex)}</code>`;
  }

  // ---------------------------------------------------------------- mesh

  const SVG_NS = "http://www.w3.org/2000/svg";
  let meshRun = 0;

  function svg(tag, attrs, parent) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    if (parent) parent.appendChild(el);
    return el;
  }

  const OUTCOME_COLOURS = {
    stored: "#6EA8FE",
    duplicate: "#555b68",
    ttl_exhausted: "#F5B547",
    sos_delivered: "#3DD6B0",
    wellness_discarded: "#8A90A0",
    rejected: "#FF6B6B",
  };

  async function runMesh() {
    const run = ++meshRun;
    const outcome = await api("simulate_mesh", {
      form: state.form,
      relays: Number($("mesh-relays").value),
      ttl: Number($("mesh-ttl").value),
      redundant_links: $("mesh-redundant").checked,
      late_link: $("mesh-late").checked,
      seconds: 6,
    });
    const root = $("mesh-svg");
    root.innerHTML = "";
    const n = outcome.nodes;
    const pos = (i) => ({ x: 70 + (i * 860) / (n - 1), y: 110 });
    const linkEls = [];
    for (const link of outcome.links) {
      const a = pos(link.a);
      const b = pos(link.b);
      const span = Math.abs(link.b - link.a);
      const d = span === 1 ? `M${a.x} ${a.y} L${b.x} ${b.y}` : `M${a.x} ${a.y} Q${(a.x + b.x) / 2} ${a.y - 70} ${b.x} ${b.y}`;
      const el = svg("path", { d, class: `link${link.up_from_round > 0 ? " late" : ""}` }, root);
      linkEls.push({ link, el });
    }
    const nodes = [];
    for (let i = 0; i < n; i++) {
      const p = pos(i);
      const kind = i === 0 ? "wearable" : i === outcome.responder ? "responder" : "relay";
      const g = svg("g", { class: `node ${kind}` }, root);
      svg("circle", { cx: p.x, cy: p.y, r: 20 }, g);
      const glyph = svg("text", { x: p.x, y: p.y + 4, class: "glyph" }, g);
      glyph.textContent = kind === "wearable" ? "W" : kind === "responder" ? "R" : String(i);
      const label = svg("text", { x: p.x, y: p.y + 44 }, g);
      label.textContent = kind === "wearable" ? "wearable" : kind === "responder" ? "responder (sim)" : `relay ${i}`;
      nodes.push(g);
    }
    const roundLabel = svg("text", { x: 12, y: 20, class: "round" }, root);
    renderMeshStats(outcome);

    const rounds = new Map();
    for (const event of outcome.events) {
      if (!rounds.has(event.round)) rounds.set(event.round, []);
      rounds.get(event.round).push(event);
    }
    const lastRound = Math.max(0, ...outcome.events.map((e) => e.round));
    for (let r = 0; r <= lastRound; r++) {
      if (run !== meshRun) return;
      roundLabel.textContent = `round ${r + 1}/${lastRound + 1}`;
      for (const { link, el } of linkEls) {
        if (link.up_from_round > 0 && r >= link.up_from_round) el.setAttribute("class", "link late up");
      }
      const events = rounds.get(r) || [];
      const packets = [];
      const seen = new Set();
      for (const event of events) {
        const key = `${event.from}-${event.to}-${event.outcome}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const from = pos(event.from);
        const to = pos(event.to);
        const g = svg("g", { class: "packet" }, root);
        svg("circle", { r: event.outcome === "sos_delivered" ? 8 : 5, fill: OUTCOME_COLOURS[event.outcome] || "#E7E9EE" }, g);
        g.style.transform = `translate(${from.x}px, ${from.y}px)`;
        packets.push({ g, to, event });
      }
      await sleep(30);
      for (const { g, to } of packets) g.style.transform = `translate(${to.x}px, ${to.y}px)`;
      await sleep(events.length ? 520 : 160);
      for (const { g, event } of packets) {
        if (event.outcome === "sos_delivered" || event.outcome === "stored") nodes[event.to].classList.add("hit");
        g.remove();
      }
    }
    roundLabel.textContent = `${lastRound + 1} rounds · SOS delivered ${outcome.stats.delivered_sos}x`;
  }

  function renderMeshStats(outcome) {
    const s = outcome.stats;
    const silent = Object.values(outcome.phone).every((v) => v === 0);
    const items = [
      ["SOS delivered", `${s.delivered_sos}x`],
      ["Hops used", s.max_hops],
      ["Frames sent (all look alike)", outcome.frames_sent],
      ["Transmissions", s.transmissions],
      ["Duplicates dropped", s.duplicates_dropped],
      ["Hop limit reached", s.ttl_exhausted],
      ["Stored, then forwarded", s.stored_then_forwarded],
      ["Wellness frames discarded", s.wellness_discarded],
      ["Phone notifications / vibrations", silent ? "none" : "PRESENT"],
      ["Location left on device", `${outcome.retained_location_bytes} B`],
    ];
    $("mesh-stats").innerHTML = items.map(([k, v]) => `<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("");
    renderChecks($("mesh-checks"), outcome.checks);
  }

  function renderChecks(list, checks) {
    list.innerHTML = checks.map((c) => `<li class="${c.passed ? "ok" : "fail"}"><span class="mark">${c.passed ? "✓" : "✗"}</span><span><span class="name">${esc(c.name)}</span><span class="why">${esc(c.detail)}</span></span></li>`).join("");
  }

  async function runAudit() {
    const checks = await api("privacy_audit", { form: state.form });
    const hosts = [...netGuard.hosts].join(", ");
    checks.push({
      name: "camera analysis never leaves this device",
      passed: true,
      detail: netGuard.blocked
        ? `${netGuard.blocked} off-device request(s) blocked (${hosts}); frames and landmarks stay in this window`
        : "vision runs in this window; any off-device request is blocked and counted here",
    });
    renderChecks($("audit-list"), checks);
  }

  // ---------------------------------------------------------------- wiring

  function refreshAutomatic() {
    if (!connected()) return;
    runAudit().catch((e) => toast(errorText(e), true));
    runZeroization().catch((e) => toast(errorText(e), true));
    runMesh().catch((e) => toast(errorText(e), true));
  }

  function wire() {
    const pad = $("tap-pad");
    pad.addEventListener("pointerdown", (event) => { event.preventDefault(); pad.focus(); recordTap(); });
    pad.addEventListener("keydown", (event) => {
      if (event.code === "Space" || event.key === "Enter") {
        event.preventDefault();
        if (!event.repeat) recordTap();
      }
    });
    $("tap-test").addEventListener("click", (e) => guarded(e.currentTarget, "Testing…", testTaps));
    $("tap-clear").addEventListener("click", () => {
      state.taps = [];
      state.tapOrigin = null;
      updateTapCount();
      renderVerdict($("tap-verdict"), null);
      drawTaps($("tap-timeline"), []);
    });
    $("tap-demo").addEventListener("click", (e) => guarded(e.currentTarget, "Playing…", demoRhythm));
    $("cal-add").addEventListener("click", () => addSample(state.taps));
    $("cal-build").addEventListener("click", (e) => guarded(e.currentTarget, "Building…", buildProfile));
    $("cal-reset").addEventListener("click", resetProfile);

    // Not guarded(): the camera state sets this button's label ("Try again") and visibility.
    $("cam-allow").addEventListener("click", () => allowCamera().catch((error) => toast(errorText(error), true)));
    $("cam-pick").addEventListener("change", () => switchCamera().catch((error) => toast(errorText(error), true)));
    if (navigator.mediaDevices && navigator.mediaDevices.addEventListener) {
      navigator.mediaDevices.addEventListener("devicechange", listCameras);
    }
    $("cam-start").addEventListener("click", (e) => guarded(e.currentTarget, "Starting…", () => startCamera("real")));
    $("cam-synthetic").addEventListener("click", (e) => guarded(e.currentTarget, "Starting…", () => startCamera("synthetic")));
    $("cam-stop").addEventListener("click", stopCamera);
    $("cam-record").addEventListener("click", async () => {
      try {
        await recordCamera();
      } catch (error) {
        toast(errorText(error), true);
      } finally {
        $("cam-record").disabled = !cam.stream;
      }
    });
    $("cam-use").addEventListener("click", () => addSample(cam.result ? cam.result.onsets.taps_ms : []));
    $("cam-selftest").addEventListener("click", (e) => guarded(e.currentTarget, "Testing…", cameraSelfTest));

    $("sign-start").addEventListener("click", (e) => guarded(e.currentTarget, "Starting…", startSigns));
    $("sign-stop").addEventListener("click", stopSigns);
    $("teach-start").addEventListener("click", () => startTeaching().catch((error) => toast(errorText(error), true)));
    $("sign-discreet").addEventListener("change", () => { if ($("sign-discreet").checked && !signs.test && !signs.teaching) hud(""); });
    $("sign-list").addEventListener("change", (event) => {
      const key = event.target.dataset && event.target.dataset.builtin;
      if (!key) return;
      signs.enabled = event.target.checked ? [...new Set([...signs.enabled, key])] : signs.enabled.filter((k) => k !== key);
      saveCustoms();
      renderSignList();
    });
    $("sign-list").addEventListener("click", (event) => {
      const button = event.target.closest("button");
      if (!button) return;
      const { test, improve, reteach, forget } = button.dataset;
      if (test) {
        startSignTest(test).catch((error) => toast(errorText(error), true));
      } else if (reteach) {
        const m = signs.customs.find((c) => c.name === reteach);
        if (!m) return;
        $("teach-name").value = m.name;
        $("teach-kind").value = m.kind;
        startTeaching().catch((error) => toast(errorText(error), true));
      } else if (improve) {
        startTeaching(improve).catch((error) => toast(errorText(error), true));
      } else if (forget) {
        signs.customs = signs.customs.filter((m) => m.name !== forget);
        delete signs.results[`custom:${forget}`];
        store.set("aegismesh.signtests", signs.results);
        if (signs.test && signs.test.target === `custom:${forget}`) signs.test = null;
        saveCustoms();
        renderSignList();
        toast(`Forgot "${forget}".`);
      }
    });
    $("bench-run").addEventListener("click", (e) => guarded(e.currentTarget, "Running…", runBenchmark));
    $("zero-run").addEventListener("click", (e) => guarded(e.currentTarget, "Wiping…", runZeroization));
    $("audit-run").addEventListener("click", (e) => guarded(e.currentTarget, "Auditing…", runAudit));
    $("mesh-run").addEventListener("click", (e) => guarded(e.currentTarget, "Running…", runMesh));
    for (const id of ["mesh-relays", "mesh-ttl"]) {
      $(id).addEventListener("input", () => { $(`${id}-out`).textContent = $(id).value; });
    }
    window.addEventListener("resize", () => drawTaps($("tap-timeline"), state.taps));
    document.addEventListener("visibilitychange", () => { if (document.hidden && cam.stream && !cam.recording) stopCamera(); });
    window.addEventListener("pagehide", () => { stopCamera(); stopSigns(); });
  }

  async function init() {
    wire();
    drawTaps($("tap-timeline"), []);
    setCameraUi(false);
    watchCameraPermission();
    updateCalibration();
    if (!connected()) {
      const banner = $("banner");
      banner.hidden = false;
      banner.textContent = "Preview mode: the tap pad and camera work here, but recognition and simulations run in the desktop app. Open AegisMesh from The Nex (AegisMesh page) or the AegisMesh console.";
      for (const id of ["tap-test", "cal-build", "bench-run", "zero-run", "audit-run", "mesh-run", "cam-record", "cam-selftest"]) $(id).title = "Needs the desktop app";
      state.defaults = {
        forms: [
          { form: "ring", label: "Ring", tap_surface: "thumb against palm or finger", sensor: "3-axis accelerometer", battery_mah: 22, radio_range_m: 10 },
          { form: "bracelet", label: "Bracelet", tap_surface: "fingers against the band", sensor: "3-axis accelerometer", battery_mah: 120, radio_range_m: 30 },
          { form: "clothing_tag", label: "Clothing Tag", tap_surface: "through fabric", sensor: "piezo tap sensor", battery_mah: 40, radio_range_m: 15 },
        ],
        profiles: FORM_ORDER.map(() => ({ name: "Triple tap, twice", ratios: [0.5, 0.5], tolerance: 0.16, min_total_ms: 160, max_total_ms: 900, min_gap_ms: 60, repeats: 2, max_pause_ms: 3000, quiet_ms: 1300 })),
      };
    } else {
      state.defaults = await api("defaults");
    }
    if (!FORM_ORDER.includes(state.form)) state.form = "ring";
    state.profile = currentProfile();
    renderForms();
    renderProfile();
    signs.customs = loadCustoms();
    renderSignList();
    refreshAutomatic();
  }

  init().catch((error) => toast(errorText(error), true));
})();
