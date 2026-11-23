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
    let pos = thin(samples, 40);
    const neg = thin(neutral, 40);
    // A held sign is a dense cluster; frames caught while moving into or out of it form a thin
    // trail. Leaving them in would widen the sign to cover in-between poses, so drop them: a
    // frame whose 6th-nearest fellow example is over 3x the usual distance is on such a trail
    // (held frames, even of a sign taught two ways, stay near 2x).
    if (pos.length >= 16) {
      const reach = pos.map((v, i) => {
        const ds = [];
        for (let j = 0; j < pos.length; j++) if (j !== i) ds.push(euclid(v, pos[j]));
        ds.sort((a, b) => a - b);
        return ds[Math.min(5, ds.length - 1)];
      });
      const typical = median(reach);
      const kept = pos.filter((v, i) => reach[i] <= typical * 3);
      if (kept.length >= pos.length * 0.75) pos = kept;
    }
    const spread = median(pos.map((v, i) => knn(v, pos, 2, i)));
    const radius = Math.max(spread * 3.0, kind === "face" ? 0.12 : 0.08);
    const separation = median(neg.map((v) => knn(v, pos, 3))) / radius;
    const selfHit = pos.filter((v, i) => knn(v, pos, 3, i) < radius).length / pos.length;
    const quality = separation >= 2 && selfHit >= 0.9 ? "good" : separation >= 1.3 ? "fair" : "poor";
    return { name: String(name).trim().slice(0, 40), kind, pos, neg, radius, separation, quality };
  }

  /**
   * Teaches more examples of an existing sign (another angle, distance or light) or its
   * ordinary pose; old and new examples are learned together.
   */
  function improveSign(model, { samples = [], neutral = [] }) {
    return trainSign({
      name: model.name,
      kind: model.kind,
      samples: [...thin(model.pos, 30), ...samples],
      neutral: [...thin(model.neg, 30), ...neutral],
    });
  }

  /**
   * How one frame compares with a trained sign: score < 1 is inside the sign's radius, and
   * `match` also requires it to be clearly nearer the sign than the person's ordinary pose.
   */
  function signDistance(m, vector) {
    if (!vector || !m.pos.length || vector.length !== m.pos[0].length) return null;
    const dPos = knn(vector, m.pos, 3);
    const dNeg = knn(vector, m.neg, 3);
    const score = dPos / m.radius;
    return { kind: m.kind, score, match: score < 1 && dPos < dNeg * 0.8 };
  }

  /** Best matching trained sign for one frame's feature vector, or null. */
  function matchSign(models, vector, kind) {
    let best = null;
    for (const m of models) {
      if (m.kind !== kind) continue;
      const d = signDistance(m, vector);
      if (d && d.match && (!best || d.score < best.score)) {
        best = { name: m.name, kind, score: d.score, confidence: Math.max(0, Math.min(1, 1 - d.score)) };
      }
    }
    return best;
  }

  // ------------------------------------------------------------------ movements
  // A movement is the path the hand travels (a wave, a circle, a swipe), whatever shape the hand
  // makes. Each frame gives the palm centre; a path is resampled evenly along its length, centred
  // on itself and measured in palm lengths, so a near and a far hand trace the same path. Paths
  // are compared with dynamic time warping, so a slightly faster or slower movement still matches.

  const MOVE_POINTS = 32;
  const MOVE_MIN_FRAMES = 8;
  const MOVE_WINDOWS = [0.7, 0.85, 1, 1.2, 1.4]; // live windows, as multiples of the taught duration

  /** Palm centre and palm length of one hand, in image units (x scaled by the aspect ratio). */
  function palmPoint(landmarks, aspect) {
    const k = aspect || 1;
    const at = (i) => ({ x: landmarks[i].x * k, y: landmarks[i].y });
    const w = at(WRIST);
    const a = at(INDEX_MCP);
    const m = at(MIDDLE_MCP);
    const b = at(PINKY_MCP);
    return {
      x: (w.x + a.x + m.x + b.x) / 4,
      y: (w.y + a.y + m.y + b.y) / 4,
      size: Math.max(Math.hypot(m.x - w.x, m.y - w.y), 1e-3),
    };
  }

  function pathLength(pts) {
    let total = 0;
    for (let i = 1; i < pts.length; i++) total += Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    return total;
  }

  /** How far the path reaches: the larger side of its bounding box. */
  function pathExtent(pts) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const q of pts) { x0 = Math.min(x0, q.x); y0 = Math.min(y0, q.y); x1 = Math.max(x1, q.x); y1 = Math.max(y1, q.y); }
    return Math.max(x1 - x0, y1 - y0);
  }

  /** `n` points spaced evenly along the path. */
  function resamplePath(points, n = MOVE_POINTS) {
    const pts = points.map((q) => ({ x: q.x, y: q.y }));
    const interval = pathLength(pts) / (n - 1);
    if (!(interval > 1e-9)) return Array.from({ length: n }, () => ({ x: pts[0].x, y: pts[0].y }));
    const out = [{ x: pts[0].x, y: pts[0].y }];
    let walked = 0;
    for (let i = 1; i < pts.length; i++) {
      const d = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
      if (d > 0 && walked + d >= interval) {
        const u = (interval - walked) / d;
        const q = { x: pts[i - 1].x + u * (pts[i].x - pts[i - 1].x), y: pts[i - 1].y + u * (pts[i].y - pts[i - 1].y) };
        out.push(q);
        pts.splice(i, 0, q);
        walked = 0;
      } else {
        walked += d;
      }
    }
    while (out.length < n) out.push({ x: pts[pts.length - 1].x, y: pts[pts.length - 1].y });
    return out.slice(0, n);
  }

  /** Frames [{x, y, size}] as a normalised path: in palm lengths, resampled, centred. */
  function movePath(frames) {
    const size = median(frames.map((f) => f.size));
    const pts = resamplePath(frames.map((f) => ({ x: f.x / size, y: f.y / size })));
    let cx = 0;
    let cy = 0;
    for (const q of pts) { cx += q.x; cy += q.y; }
    cx /= pts.length;
    cy /= pts.length;
    return pts.map((q) => ({ x: q.x - cx, y: q.y - cy }));
  }

  /** Average distance per step between two paths after dynamic time warping (banded). */
  function dtw(a, b, band = 5) {
    const n = a.length;
    const m = b.length;
    let prev = new Float64Array(m + 1).fill(Infinity);
    prev[0] = 0;
    for (let i = 1; i <= n; i++) {
      const cur = new Float64Array(m + 1).fill(Infinity);
      const lo = Math.max(1, i - band);
      const hi = Math.min(m, i + band);
      for (let j = lo; j <= hi; j++) {
        const d = Math.hypot(a[i - 1].x - b[j - 1].x, a[i - 1].y - b[j - 1].y);
        cur[j] = d + Math.min(prev[j], cur[j - 1], prev[j - 1]);
      }
      prev = cur;
    }
    return prev[m] / n;
  }

  /** Drops the still moments before the hand starts moving and after it stops. */
  function trimStill(frames) {
    if (frames.length < 3) return frames;
    const size = median(frames.map((f) => f.size));
    const moved = (i, j) => Math.hypot(frames[i].x - frames[j].x, frames[i].y - frames[j].y) / size;
    const last = frames.length - 1;
    let start = 0;
    while (start < last && moved(start, 0) < 0.2) start++;
    let end = last;
    while (end > start && moved(end, last) < 0.2) end--;
    return frames.slice(Math.max(0, start - 1), Math.min(frames.length, end + 2));
  }

  /**
   * Learns a movement from a few recordings of it (each: frames [{t, x, y, size}] from
   * palmPoint). `base`, an earlier model of the same movement, keeps its examples (add examples).
   */
  function trainMovement({ name, recordings = [], base = null }) {
    if (!name || !String(name).trim()) throw new Error("give the movement a name");
    const usable = recordings.map(trimStill).filter((r) => r.length >= MOVE_MIN_FRAMES);
    const paths = [...(base ? base.templates : []), ...usable.map(movePath)].slice(-6);
    const durations = [...(base ? [base.duration] : []), ...usable.map((r) => r[r.length - 1].t - r[0].t)];
    if (paths.length < 2) {
      const seen = recordings.filter((r) => r.length >= MOVE_MIN_FRAMES).length + (base ? base.templates.length : 0);
      throw new Error(seen >= 2
        ? "the movement was too small: move your hand at least about a hand's length"
        : "the camera saw your hand move in fewer than 2 of the recordings: keep your whole hand in view and move it clearly");
    }
    const amplitude = median(paths.map(pathLength));
    const extent = median(paths.map(pathExtent));
    if (extent < 0.8 || amplitude < 1.2) throw new Error("the movement was too small: move your hand at least about a hand's length");
    const pairs = [];
    for (let i = 0; i < paths.length; i++) for (let j = i + 1; j < paths.length; j++) pairs.push(dtw(paths[i], paths[j]));
    const spread = median(pairs);
    const radius = Math.max(spread * 2.2, 0.22);
    const still = Array.from({ length: MOVE_POINTS }, () => ({ x: 0, y: 0 }));
    const separation = median(paths.map((q) => dtw(q, still))) / radius;
    const worst = Math.max(...pairs) / radius;
    const quality = separation >= 2.2 && worst <= 1 ? "good" : separation >= 1.4 && worst <= 1.5 ? "fair" : "poor";
    return {
      name: String(name).trim().slice(0, 40),
      kind: "move",
      templates: paths,
      duration: median(durations),
      amplitude,
      extent,
      radius,
      separation,
      quality,
    };
  }

  /**
   * How the hand's recent path compares with a taught movement: the best of a few window lengths
   * ending now. score < 1 is a match; a hand that barely moved never matches.
   */
  function movementDistance(m, frames, now) {
    if (!m.templates || !m.templates.length) return null;
    let best = null;
    for (const f of MOVE_WINDOWS) {
      const span = m.duration * f;
      const win = frames.filter((q) => now - q.t <= span);
      if (win.length < MOVE_MIN_FRAMES || win[win.length - 1].t - win[0].t < span * 0.8) continue;
      const path = movePath(win);
      if (pathLength(path) < m.amplitude * 0.55 || pathExtent(path) < (m.extent || 0) * 0.5) continue;
      for (const tpl of m.templates) {
        const d = dtw(path, tpl) / m.radius;
        if (best === null || d < best) best = d;
      }
    }
    if (best === null) return { kind: "move", score: 9, match: false };
    return { kind: "move", score: best, match: best < 1 };
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
      this.palm = []; // recent palm positions, for taught movements
      this.lastHandAt = -Infinity;
    }

    setCustoms(customs) {
      this.customs = customs;
    }

    update(frame) {
      const t = frame.t;
      const events = [];
      // scores: for every taught sign, how close this frame came (its best hand or the face).
      const status = { handState: null, faceState: null, custom: null, scores: {}, progress: {} };
      const note = (vector, kind) => {
        for (const m of this.customs) {
          if (m.kind !== kind) continue;
          const d = signDistance(m, vector);
          if (d && (!status.scores[m.name] || d.score < status.scores[m.name].score)) status.scores[m.name] = d;
        }
      };
      const moves = this.customs.filter((m) => m.kind === "move");
      const first = (frame.hands || [])[0];
      if (first) {
        this.palm.push({ t, ...palmPoint(first.landmarks, frame.aspect) });
        this.lastHandAt = t;
      } else if (t - this.lastHandAt > 300) {
        this.palm = [];
      }
      const keep = moves.reduce((most, m) => Math.max(most, m.duration * MOVE_WINDOWS[MOVE_WINDOWS.length - 1] + 200), 0);
      while (this.palm.length && t - this.palm[0].t > keep) this.palm.shift();
      for (const m of moves) {
        const d = movementDistance(m, this.palm, t);
        if (d) status.scores[m.name] = d;
      }
      let handLabel = "none";
      for (const hand of frame.hands || []) {
        const p = normalizeHand(hand.landmarks, hand.handedness, frame.aspect);
        const state = handState(p);
        if (handLabel === "none" || state === "open_thumb_tucked" || state === "folded") handLabel = state;
        note(handFeatures(p), "hand");
      }
      status.handState = handLabel;
      const scores = faceScores(frame.face);
      let faceLabel = "none";
      if (scores) {
        faceLabel = faceState(scores);
        note(faceFeatures(scores), "face");
      }
      status.faceState = faceLabel;
      // Held signs and expressions go through the hold voter; a movement counts the moment it ends.
      let best = null;
      let moved = null;
      for (const [name, d] of Object.entries(status.scores)) {
        if (!d.match) continue;
        const hit = { name, kind: d.kind, score: d.score, confidence: Math.max(0, Math.min(1, 1 - d.score)) };
        if (d.kind === "move") {
          if (!moved || d.score < moved.score) moved = hit;
        } else if (!best || d.score < best.score) {
          best = hit;
        }
      }
      status.custom = best || moved;

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
      if (moved && !cooling && !events.length) {
        events.push({ sign: `custom:${moved.name}`, name: moved.name, kind: "move" });
        this.palm = [];
      }
      if (events.length) this.cooldownUntil = t + 4000;
      return { events, status };
    }
  }

  /**
   * A rehearsal of one sign: feed it each frame's SignWatcher output for up to `timeoutMs`. It
   * reports whether the sign was recognised and how fast, or else the most likely reason.
   * target: "signal_for_help", "double_wink" or "custom:<name>"; kind: "hand" or "face".
   */
  function makeSignTest(target, kind, { timeoutMs = 10000 } = {}) {
    const custom = target.startsWith("custom:") ? target.slice(7) : null;
    const n = { frames: 0, seen: 0, match: 0, nearNeutral: 0, unlike: 0 };
    let start = null;
    let best = 0;
    let other = null;
    let result = null;

    function advice() {
      const what = kind === "face" ? "face" : "hand";
      const lead = other ? `It recognised "${other}" instead. ` : "";
      if (n.seen < n.frames * 0.3) return `${lead}The camera hardly saw your ${what}: face it from about an arm's length away, in good light.`;
      if (custom && kind === "move") {
        return `${lead}It never looked like the movement you taught: make it about the same size and speed, with your whole hand in view the whole time.`;
      }
      if (custom) {
        if (n.match > 0) return `${lead}It matched only in moments: hold the sign still for a full second.`;
        if (n.nearNeutral >= n.unlike) return `${lead}It looked too much like your ordinary ${what}: teach a more distinctive sign.`;
        return `${lead}It never looked like the sign you taught: make it the way you taught it, or press "add examples" to teach it from here.`;
      }
      if (target === "signal_for_help") {
        return lead + (best < 0.5
          ? "The open palm with the thumb tucked in was not seen: palm flat to the camera, fingers up, thumb folded across the palm."
          : "The tucked thumb was seen but not the fold: then fold all four fingers down over the thumb within 2 seconds.");
      }
      if (target === "double_wink") {
        return lead + (best < 0.5
          ? "No clear wink was seen: close one eye fully while the other stays open."
          : "One wink was seen: wink the other eye within a second and a half.");
      }
      return `${lead}It was not recognised.`;
    }

    return {
      target,
      get result() { return result; },
      /** seen: whether a hand (for a hand sign) or a face (for an expression) was in this frame. */
      update(t, events, status, seen) {
        if (result) return result;
        if (start === null) start = t;
        const elapsed = t - start;
        n.frames++;
        if (seen) n.seen++;
        if (events.some((e) => e.sign === target)) {
          result = { passed: true, ms: elapsed, best: 1 };
          return result;
        }
        const otherEvent = events.find((e) => e.sign !== target);
        if (otherEvent) other = otherEvent.name;
        let progress = 0;
        if (custom) {
          const d = status.scores && status.scores[custom];
          if (d) {
            if (d.match) n.match++;
            else if (d.score < 1) n.nearNeutral++;
            else n.unlike++;
          }
          if (d && d.kind === "move") progress = Math.max(0, Math.min(1, 1.6 - d.score));
          else if (status.custom && status.custom.name === custom) progress = status.progress.custom || 0;
        } else {
          progress = status.progress[target] || 0;
        }
        best = Math.max(best, progress);
        if (elapsed >= timeoutMs) {
          result = { passed: false, ms: elapsed, best, advice: advice() };
          return result;
        }
        return { passed: null, ms: elapsed, left: timeoutMs - elapsed, progress, best };
      },
    };
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
    improveSign,
    palmPoint,
    movePath,
    trainMovement,
    movementDistance,
    signDistance,
    matchSign,
    makeSequence,
    makeHoldVoter,
    SignWatcher,
    makeSignTest,
  };
});
