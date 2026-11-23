// AegisMesh sign and expression recogniser. Pure functions over landmark data from the on-device
// vision models; no DOM, no network. Works in the console page (window.AegisSigns) and in Node
// (scripts/test_signs.js).
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.AegisSigns = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // MediaPipe hand landmark indices.
  const WRIST = 0;
  const THUMB_TIP = 4;
  const INDEX_MCP = 5;
  const MIDDLE_MCP = 9;
  const RING_MCP = 13;
  const PINKY_MCP = 17;
  const FINGERS = [[5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16], [17, 18, 19, 20]];

  // MediaPipe / ARKit face blendshapes (without "_neutral").
  const FACE_KEYS = [
    "browDownLeft", "browDownRight", "browInnerUp", "browOuterUpLeft", "browOuterUpRight",
    "cheekPuff", "cheekSquintLeft", "cheekSquintRight", "eyeBlinkLeft", "eyeBlinkRight",
    "eyeLookDownLeft", "eyeLookDownRight", "eyeLookInLeft", "eyeLookInRight", "eyeLookOutLeft",
    "eyeLookOutRight", "eyeLookUpLeft", "eyeLookUpRight", "eyeSquintLeft", "eyeSquintRight",
    "eyeWideLeft", "eyeWideRight", "jawForward", "jawLeft", "jawOpen", "jawRight", "mouthClose",
    "mouthDimpleLeft", "mouthDimpleRight", "mouthFrownLeft", "mouthFrownRight", "mouthFunnel",
    "mouthLeft", "mouthLowerDownLeft", "mouthLowerDownRight", "mouthPressLeft", "mouthPressRight",
    "mouthPucker", "mouthRight", "mouthRollLower", "mouthRollUpper", "mouthShrugLower",
    "mouthShrugUpper", "mouthSmileLeft", "mouthSmileRight", "mouthStretchLeft", "mouthStretchRight",
    "mouthUpperUpLeft", "mouthUpperUpRight", "noseSneerLeft", "noseSneerRight",
  ];
  // Where someone looks changes these constantly; they matter little for an expression.
  const FACE_WEIGHTS = FACE_KEYS.map((k) => (k.startsWith("eyeLook") ? 0.3 : 1.0));

  const sub = (a, b) => ({ x: a.x - b.x, y: a.y - b.y, z: a.z - b.z });
  const dist2 = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  const mid = (a, b) => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, z: (a.z + b.z) / 2 });
  function angle3(a, b) {
    const la = Math.hypot(a.x, a.y, a.z);
    const lb = Math.hypot(b.x, b.y, b.z);
    if (la < 1e-9 || lb < 1e-9) return 0;
    const c = (a.x * b.x + a.y * b.y + a.z * b.z) / (la * lb);
    return Math.acos(Math.max(-1, Math.min(1, c)));
  }

  /**
   * Hand landmarks in a canonical frame: wrist at the origin, palm length (wrist to middle-finger
   * knuckle) = 1 pointing up, left hands mirrored onto right hands. `aspect` = width / height of
   * the image the normalised landmarks came from (x and y are normalised separately).
   */
  function normalizeHand(landmarks, handedness, aspect) {
    const k = aspect || 1;
    const pts = landmarks.map((p) => ({ x: p.x * k, y: p.y, z: (p.z || 0) * k }));
    const w = pts[WRIST];
    const m = pts[MIDDLE_MCP];
    const dx = m.x - w.x;
    const dy = m.y - w.y;
    const scale = Math.hypot(dx, dy) || 1e-6;
    const theta = Math.atan2(dx, -dy);
    const cos = Math.cos(-theta);
    const sin = Math.sin(-theta);
    const mirror = handedness === "Left";
    return pts.map((p) => {
      const x = (p.x - w.x) / scale;
      const y = (p.y - w.y) / scale;
      const rx = x * cos - y * sin;
      return { x: mirror ? -rx : rx, y: x * sin + y * cos, z: (p.z - w.z) / scale };
    });
  }

  /** Per finger: tip distance / middle-joint distance from the wrist, and joint bend (radians). */
  function fingerShape(p) {
    return FINGERS.map(([mcp, pip, dip, tip]) => ({
      ratio: dist2(p[tip], p[WRIST]) / Math.max(dist2(p[pip], p[WRIST]), 1e-6),
      bend: angle3(sub(p[pip], p[mcp]), sub(p[tip], p[dip])),
    }));
  }
  const extended = (f) => f.ratio > 1.15 && f.bend < 1.0;
  const curled = (f) => f.ratio < 1.0 || f.bend > 1.9;

  /** Thumb tip distance from the palm centre (between middle and ring knuckles), in palm lengths. */
  function thumbReach(p) {
    return dist2(p[THUMB_TIP], mid(p[MIDDLE_MCP], p[RING_MCP]));
  }

  /** Coarse hand state used by the built-in Signal for Help. */
  function handState(p) {
    if (dist2(p[INDEX_MCP], p[PINKY_MCP]) < 0.4) return "edge_on";
    const fingers = fingerShape(p);
    const reach = thumbReach(p);
    if (fingers.every(extended)) return reach < 0.55 ? "open_thumb_tucked" : reach >= 0.75 ? "open" : "other";
    if (fingers.every(curled)) return reach < 0.75 ? "folded" : "fist_thumb_out";
    return "other";
  }

  function handFeatures(p) {
    const v = [];
    for (let i = 1; i < p.length; i++) v.push(p[i].x, p[i].y, p[i].z * 0.5);
    for (const f of fingerShape(p)) v.push(f.ratio * 0.8, f.bend * 0.5);
    v.push(thumbReach(p));
    return v;
  }

  /** Blendshape categories ([{categoryName, score}] or {name: score}) to a feature vector. */
  function faceScores(blendshapes) {
    if (!blendshapes) return null;
    if (Array.isArray(blendshapes)) {
      const out = {};
      for (const c of blendshapes) out[c.categoryName] = c.score;
      return out;
    }
    return blendshapes;
  }

  function faceFeatures(scores) {
    return FACE_KEYS.map((k, i) => (scores[k] || 0) * 2 * FACE_WEIGHTS[i]);
  }

  /** Coarse face state used by the built-in double wink. */
  function faceState(scores) {
    const l = scores.eyeBlinkLeft || 0;
    const r = scores.eyeBlinkRight || 0;
    if (l > 0.5 && r > 0.5) return "blink";
    if (l > 0.5 && r < 0.35 && l - r > 0.3) return "wink_left";
    if (r > 0.5 && l < 0.35 && r - l > 0.3) return "wink_right";
    return "neutral";
  }

  // ------------------------------------------------------------------ distances and training

  function euclid(a, b) {
    let s = 0;
    for (let i = 0; i < a.length; i++) {
      const d = a[i] - b[i];
      s += d * d;
    }
    return Math.sqrt(s);
  }

  /** Mean distance to the k nearest vectors in `set` (skipping index `skip`). */
  function knn(v, set, k, skip = -1) {
    const ds = [];
    for (let i = 0; i < set.length; i++) if (i !== skip) ds.push(euclid(v, set[i]));
    ds.sort((a, b) => a - b);
    const n = Math.min(k, ds.length);
    if (!n) return Infinity;
    let s = 0;
    for (let i = 0; i < n; i++) s += ds[i];
    return s / n;
  }

  function median(values) {
    if (!values.length) return 0;
    const s = values.slice().sort((a, b) => a - b);
    const m = s.length >> 1;
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  function thin(vectors, max) {
    if (vectors.length <= max) return vectors.slice();
    const step = vectors.length / max;
    return Array.from({ length: max }, (_, i) => vectors[Math.floor(i * step)]);
  }

  const MIN_FRAMES = 8;

  /**
   * Learns one sign or expression from frames of it (`samples`) and frames of the person's
   * ordinary pose (`neutral`). The acceptance radius comes from how tightly the examples
   * cluster; `separation` says how clearly the sign stands apart from the ordinary pose.
   */
  function trainSign({ name, kind, samples, neutral }) {
    if (!name || !String(name).trim()) throw new Error("give the sign a name");
    if (kind !== "hand" && kind !== "face") throw new Error("kind must be hand or face");
    if (!samples || samples.length < MIN_FRAMES) throw new Error(`hold the sign a little longer (${MIN_FRAMES}+ frames needed)`);
    if (!neutral || neutral.length < MIN_FRAMES) throw new Error(`record your normal ${kind === "hand" ? "hand" : "face"} for a little longer (${MIN_FRAMES}+ frames needed)`);
    const pos = thin(samples, 40);
    const neg = thin(neutral, 40);
    const spread = median(pos.map((v, i) => knn(v, pos, 2, i)));
    const radius = Math.max(spread * 3.0, kind === "face" ? 0.12 : 0.08);
    const separation = median(neg.map((v) => knn(v, pos, 3))) / radius;
    const selfHit = pos.filter((v, i) => knn(v, pos, 3, i) < radius).length / pos.length;
    const quality = separation >= 2 && selfHit >= 0.9 ? "good" : separation >= 1.3 ? "fair" : "poor";
    return { name: String(name).trim().slice(0, 40), kind, pos, neg, radius, separation, quality };
  }

  /** Best matching trained sign for one frame's feature vector, or null. */
  function matchSign(models, vector, kind) {
    let best = null;
    for (const m of models) {
      if (m.kind !== kind || !vector || vector.length !== m.pos[0].length) continue;
      const dPos = knn(vector, m.pos, 3);
      const dNeg = knn(vector, m.neg, 3);
      const score = dPos / m.radius;
      if (score < 1 && dPos < dNeg * 0.8 && (!best || score < best.score)) {
        best = { name: m.name, kind, score, confidence: Math.max(0, Math.min(1, 1 - score)) };
      }
    }
    return best;
  }

  // ------------------------------------------------------------------ temporal logic

  /**
   * Ordered steps (state labels), each held for `holdMs`, the next one starting within `gapMs`.
   * Up to `graceMs` of contrary frames inside a hold are forgiven (detector jitter).
   */
  function makeSequence(steps, { holdMs = 200, gapMs = 2000, graceMs = 140 } = {}) {
    let step = 0;
    let since = null;
    let lastGood = null;
    let completedAt = null;
    function reset() {
      step = 0;
      since = null;
      lastGood = null;
      completedAt = null;
    }
    function update(label, t) {
      if (completedAt !== null && step > 0 && since === null && t - completedAt > gapMs) reset();
      if (label === steps[step]) {
        if (since === null) since = t;
        lastGood = t;
        if (t - since >= holdMs) {
          step += 1;
          since = null;
          completedAt = t;
          if (step === steps.length) {
            reset();
            return { done: true, progress: 1 };
          }
        }
      } else if (since !== null && t - lastGood > graceMs) {
        since = null;
      } else if (since === null && step > 0 && label === steps[step - 1]) {
        completedAt = t; // still holding the previous step: the gap clock starts when it ends
      }
      return { done: false, progress: step / steps.length };
    }
    return { update, reset, get step() { return step; } };
  }

  /** Fires `label` once it has filled at least `ratio` of the last `holdMs`. */
  function makeHoldVoter({ holdMs = 900, ratio = 0.75, cooldownMs = 4000 } = {}) {
    let history = [];
    let cooldownUntil = -Infinity;
    return function vote(label, t) {
      history.push({ label, t });
      while (history.length && t - history[0].t > holdMs) history.shift();
      if (!label || t < cooldownUntil || history.length < 6 || t - history[0].t < holdMs * 0.8) {
        return { fired: null, progress: label ? Math.min(1, history.filter((h) => h.label === label).length / Math.max(6, history.length)) : 0 };
      }
      const share = history.filter((h) => h.label === label).length / history.length;
      if (share >= ratio) {
        cooldownUntil = t + cooldownMs;
        history = [];
        return { fired: label, progress: 1 };
      }
      return { fired: null, progress: share };
    };
  }

  const BUILTINS = {
    signal_for_help: {
      name: "Signal for Help",
      kind: "hand",
      how: "Palm to the camera, tuck your thumb into the palm, then fold your fingers down over it.",
    },
    double_wink: {
      name: "Wink, then the other eye",
      kind: "face",
      how: "Wink one eye, then the other within a second and a half.",
    },
  };

  /**
   * Consumes one processed video frame and reports what it sees plus any trigger.
   * frame = { t, aspect, hands: [{ landmarks, handedness }], face: blendshapes | null }
   */
  class SignWatcher {
    constructor({ enabled = ["signal_for_help", "double_wink"], customs = [], holdMs = 900 } = {}) {
      this.enabled = new Set(enabled);
      this.customs = customs;
      this.help = makeSequence(["open_thumb_tucked", "folded"], { holdMs: 200, gapMs: 2000 });
      this.winkLR = makeSequence(["wink_left", "wink_right"], { holdMs: 100, gapMs: 1500, graceMs: 80 });
      this.winkRL = makeSequence(["wink_right", "wink_left"], { holdMs: 100, gapMs: 1500, graceMs: 80 });
      this.voter = makeHoldVoter({ holdMs });
      this.cooldownUntil = -Infinity;
    }

    setCustoms(customs) {
      this.customs = customs;
    }

    update(frame) {
      const t = frame.t;
      const events = [];
      const status = { handState: null, faceState: null, custom: null, progress: {} };
      let handLabel = "none";
      let best = null;
      for (const hand of frame.hands || []) {
        const p = normalizeHand(hand.landmarks, hand.handedness, frame.aspect);
        const state = handState(p);
        if (handLabel === "none" || state === "open_thumb_tucked" || state === "folded") handLabel = state;
        const m = matchSign(this.customs, handFeatures(p), "hand");
        if (m && (!best || m.score < best.score)) best = m;
      }
      status.handState = handLabel;
      const scores = faceScores(frame.face);
      let faceLabel = "none";
      if (scores) {
        faceLabel = faceState(scores);
        const m = matchSign(this.customs, faceFeatures(scores), "face");
        if (m && (!best || m.score < best.score)) best = m;
      }
      status.faceState = faceLabel;
      status.custom = best;

      const cooling = t < this.cooldownUntil;
      if (this.enabled.has("signal_for_help")) {
        const r = this.help.update(handLabel, t);
        status.progress.signal_for_help = r.progress;
        if (r.done && !cooling) events.push({ sign: "signal_for_help", name: BUILTINS.signal_for_help.name, kind: "hand" });
      }
      if (this.enabled.has("double_wink")) {
        const a = this.winkLR.update(faceLabel, t);
        const b = this.winkRL.update(faceLabel, t);
        status.progress.double_wink = Math.max(a.progress, b.progress);
        if ((a.done || b.done) && !cooling) {
          this.winkLR.reset();
          this.winkRL.reset();
          events.push({ sign: "double_wink", name: BUILTINS.double_wink.name, kind: "face" });
        }
      }
      const vote = this.voter(best ? best.name : null, t);
      status.progress.custom = vote.progress;
      if (vote.fired && !cooling) {
        const m = this.customs.find((c) => c.name === vote.fired);
        events.push({ sign: `custom:${vote.fired}`, name: vote.fired, kind: m ? m.kind : "hand" });
      }
      if (events.length) this.cooldownUntil = t + 4000;
      return { events, status };
    }
  }

  return {
    FACE_KEYS,
    BUILTINS,
    normalizeHand,
    fingerShape,
    thumbReach,
    handState,
    handFeatures,
    faceScores,
    faceFeatures,
    faceState,
    trainSign,
    matchSign,
    makeSequence,
    makeHoldVoter,
    SignWatcher,
  };
});
