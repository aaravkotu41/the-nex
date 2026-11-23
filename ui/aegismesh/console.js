"use strict";
// AegisMesh console. Runs standalone (aegismesh-gui) or inside The Nex (iframe, parent IPC).
// Every operation is a local simulation in aegismesh-core; the camera is analysed in-page as
// per-frame brightness change only and nothing is recorded, stored or sent.
(() => {
  const $ = (id) => document.getElementById(id);
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
    return (source, width, height) => {
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
      return energy;
    };
  }

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

  async function startCamera(kind) {
    stopCamera();
    let stream;
    if (kind === "real") {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error("This window has no camera access.");
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 30 } },
          audio: false,
        });
      } catch (error) {
        const name = error && error.name;
        if (name === "NotAllowedError" || name === "SecurityError") throw new Error("Camera permission was denied. Allow it in the prompt or in system privacy settings, or use the simulated camera.");
        if (name === "NotFoundError" || name === "OverconstrainedError") throw new Error("No camera found. Use the simulated camera or the self-test instead.");
        if (name === "NotReadableError") throw new Error("The camera is busy in another app. Close it and try again.");
        throw error;
      }
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
    renderChecks($("audit-list"), await api("privacy_audit", { form: state.form }));
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

    $("bench-run").addEventListener("click", (e) => guarded(e.currentTarget, "Running…", runBenchmark));
    $("zero-run").addEventListener("click", (e) => guarded(e.currentTarget, "Wiping…", runZeroization));
    $("audit-run").addEventListener("click", (e) => guarded(e.currentTarget, "Auditing…", runAudit));
    $("mesh-run").addEventListener("click", (e) => guarded(e.currentTarget, "Running…", runMesh));
    for (const id of ["mesh-relays", "mesh-ttl"]) {
      $(id).addEventListener("input", () => { $(`${id}-out`).textContent = $(id).value; });
    }
    window.addEventListener("resize", () => drawTaps($("tap-timeline"), state.taps));
    document.addEventListener("visibilitychange", () => { if (document.hidden && cam.stream && !cam.recording) stopCamera(); });
    window.addEventListener("pagehide", stopCamera);
  }

  async function init() {
    wire();
    drawTaps($("tap-timeline"), []);
    setCameraUi(false);
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
    refreshAutomatic();
  }

  init().catch((error) => toast(errorText(error), true));
})();
