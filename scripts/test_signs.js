#!/usr/bin/env node
// Tests for ui/aegismesh/signs.js with synthetic hands and faces: a 3-D hand model posed,
// rotated, scaled, mirrored (left hands), jittered and projected like a webcam would see it,
// and blendshape streams for faces. Run: node scripts/test_signs.js  (exit 1 on failure)
"use strict";
const path = require("path");
const S = require(path.join(__dirname, "..", "ui", "aegismesh", "signs.js"));

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures++;
}
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const uni = (r, lo, hi) => lo + (hi - lo) * r();
const gauss = (r) => Math.sqrt(-2 * Math.log(1 - r())) * Math.cos(2 * Math.PI * r());

// ---------------------------------------------------------------- synthetic hand

const MCP = { 5: [0.36, -0.93], 9: [0, -1], 13: [-0.27, -0.95], 17: [-0.5, -0.85] };
const LEN = { 5: 0.95, 9: 1, 13: 0.95, 17: 0.75 };
const SPLAY = { 5: 0.12, 9: 0, 13: -0.1, 17: -0.22 };
const SEG = [0.45, 0.28, 0.22];
const THUMBS = {
  out: [[0.28, -0.22, 0], [0.55, -0.42, 0], [0.78, -0.6, 0], [0.95, -0.78, 0]],
  tucked: [[0.28, -0.22, 0.02], [0.38, -0.48, 0.08], [0.22, -0.7, 0.12], [0.02, -0.82, 0.12]],
  wrapped: [[0.28, -0.22, 0.02], [0.42, -0.5, 0.1], [0.3, -0.75, 0.25], [0.1, -0.95, 0.3]],
};

/** Canonical right hand, palm to camera: flex 0 = straight finger, 1 = fully curled. */
function pose(flex, thumb) {
  const pts = new Array(21);
  pts[0] = { x: 0, y: 0, z: 0 };
  THUMBS[thumb].forEach(([x, y, z], i) => { pts[1 + i] = { x, y, z }; });
  [5, 9, 13, 17].forEach((mcp, f) => {
    let p = { x: MCP[mcp][0], y: MCP[mcp][1], z: 0 };
    pts[mcp] = p;
    let cum = 0;
    [80, 95, 70].forEach((deg, j) => {
      cum += (deg * flex[f] * Math.PI) / 180;
      const len = SEG[j] * LEN[mcp];
      p = {
        x: p.x + Math.sin(SPLAY[mcp]) * Math.cos(cum) * len,
        y: p.y - Math.cos(SPLAY[mcp]) * Math.cos(cum) * len,
        z: p.z + Math.sin(cum) * len,
      };
      pts[mcp + 1 + j] = p;
    });
  });
  return pts;
}

/** A camera view of one hand: random placement per session, jitter per frame. */
function camera(r) {
  return {
    rot: uni(r, -0.6, 0.6),
    scale: uni(r, 0.18, 0.4),
    cx: uni(r, 0.35, 0.65),
    cy: uni(r, 0.55, 0.75),
    left: r() < 0.5,
    aspect: r() < 0.5 ? 4 / 3 : 16 / 9,
    noise: uni(r, 0.002, 0.005),
  };
}
function view(pts, cam, r) {
  const c = Math.cos(cam.rot);
  const s = Math.sin(cam.rot);
  const landmarks = pts.map((p) => {
    const x0 = cam.left ? -p.x : p.x;
    const x = x0 * c - p.y * s;
    const y = x0 * s + p.y * c;
    return {
      x: cam.cx + (x * cam.scale) / cam.aspect + gauss(r) * cam.noise,
      y: cam.cy + y * cam.scale + gauss(r) * cam.noise,
      z: (p.z * cam.scale) / cam.aspect + gauss(r) * cam.noise,
    };
  });
  return { landmarks, handedness: cam.left ? "Left" : "Right" };
}
const lerp = (a, b, u) => a.map((v, i) => v + (b[i] - v) * u);

/**
 * Plays a script of [durationMs, flexFrom, flexTo, thumb] segments through a SignWatcher.
 * thumb "away" means no hand in the picture. opts.test: a makeSignTest fed every frame.
 */
function play(watcher, script, r, opts = {}) {
  const cam = camera(r);
  const fps = opts.fps || uni(r, 24, 30);
  const events = [];
  let t = opts.start || 0;
  for (const [ms, from, to, thumb] of script) {
    const frames = Math.max(1, Math.round((ms / 1000) * fps));
    for (let i = 0; i < frames; i++) {
      t += 1000 / fps;
      if (r() < 0.02) continue; // dropped frame
      const flex = lerp(from, to, frames === 1 ? 1 : i / (frames - 1)).map((f) => Math.min(1, Math.max(0, f + gauss(r) * 0.03)));
      const sway = opts.wave ? Math.sin(t / 180) * 0.5 : 0;
      const hands = thumb === "away" ? [] : [view(pose(flex, thumb), { ...cam, rot: cam.rot + sway }, r)];
      const out = watcher.update({ t, aspect: cam.aspect, hands, face: null });
      events.push(...out.events);
      if (opts.test && opts.test.update(t, out.events, out.status, hands.length > 0).passed !== null) return events;
    }
  }
  return events;
}

const OPEN = [0, 0, 0, 0];
const FIST = [1, 1, 1, 1];
const HALF = [0.5, 0.5, 0.5, 0.5];

console.log("hand geometry");
{
  const r = rng(1);
  const states = { open: 0, tucked: 0, folded: 0 };
  for (let i = 0; i < 300; i++) {
    const cam = camera(r);
    const n = (flex, thumb) => S.handState(S.normalizeHand(view(pose(flex, thumb), cam, r).landmarks, cam.left ? "Left" : "Right", cam.aspect));
    states.open += n(OPEN, "out") === "open";
    states.tucked += n(OPEN, "tucked") === "open_thumb_tucked";
    states.folded += n(FIST, "tucked") === "folded";
  }
  check("open palm recognised", states.open >= 290, `${states.open}/300`);
  check("palm with thumb tucked recognised", states.tucked >= 290, `${states.tucked}/300`);
  check("fingers folded over thumb recognised", states.folded >= 290, `${states.folded}/300`);
}

console.log("Signal for Help");
{
  const r = rng(2);
  let hits = 0;
  for (let i = 0; i < 300; i++) {
    const w = new S.SignWatcher({ enabled: ["signal_for_help"] });
    const ev = play(w, [
      [uni(r, 200, 600), OPEN, OPEN, "out"],
      [uni(r, 350, 800), OPEN, OPEN, "tucked"],
      [uni(r, 150, 400), OPEN, FIST, "tucked"],
      [uni(r, 350, 800), FIST, FIST, "tucked"],
    ], r);
    hits += ev.some((e) => e.sign === "signal_for_help");
  }
  check("detected at any angle, size, hand and 24-30 fps", hits >= 285, `${hits}/300`);

  const negatives = {
    "open hand then ordinary fist": [[600, OPEN, OPEN, "out"], [300, OPEN, FIST, "out"], [500, FIST, FIST, "wrapped"], [300, FIST, OPEN, "out"], [600, OPEN, OPEN, "out"]],
    "waving": [[3000, OPEN, OPEN, "out"]],
    "thumb tucked but never folded": [[2500, OPEN, OPEN, "tucked"]],
    "fold long after the tuck": [[600, OPEN, OPEN, "tucked"], [2600, HALF, HALF, "out"], [600, FIST, FIST, "tucked"]],
    // The thumb only crosses the palm once the fingers are curling, as in a natural grip.
    "relaxed fidgeting": [[800, HALF, OPEN, "out"], [800, OPEN, HALF, "out"], [800, HALF, FIST, "wrapped"], [800, FIST, HALF, "out"]],
  };
  for (const [name, script] of Object.entries(negatives)) {
    let fired = 0;
    for (let i = 0; i < 200; i++) {
      const w = new S.SignWatcher({ enabled: ["signal_for_help"] });
      fired += play(w, script, r, { wave: name === "waving" }).length > 0;
    }
    check(`no trigger: ${name}`, fired <= 2, `${fired}/200 sessions`);
  }
}

console.log("custom hand sign");
{
  const r = rng(3);
  const frames = (flex, thumb, n) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const cam = camera(r);
      const f = flex.map((x) => Math.min(1, Math.max(0, x + gauss(r) * 0.04)));
      const v = view(pose(f, thumb), cam, r);
      out.push(S.handFeatures(S.normalizeHand(v.landmarks, v.handedness, cam.aspect)));
    }
    return out;
  };
  const PEACE = [0, 0, 1, 1];
  const neutral = [...frames([0.25, 0.3, 0.3, 0.35], "out", 25), ...frames(FIST, "wrapped", 25)];
  const model = S.trainSign({ name: "Peace", kind: "hand", samples: frames(PEACE, "tucked", 50), neutral });
  check("training reports a usable sign", model.quality !== "poor", `quality ${model.quality}, separation ${model.separation.toFixed(2)}`);
  const rate = (vectors) => vectors.filter((v) => S.matchSign([model], v, "hand")).length / vectors.length;
  const own = rate(frames(PEACE, "tucked", 400));
  check("trained sign recognised on new frames", own >= 0.9, `${(own * 100).toFixed(1)}%`);
  for (const [name, flex, thumb] of [["open hand", OPEN, "out"], ["fist", FIST, "wrapped"], ["rock sign", [0, 1, 1, 0], "tucked"], ["pointing", [0, 1, 1, 1], "tucked"], ["three fingers", [0, 0, 0, 1], "tucked"]]) {
    const fp = rate(frames(flex, thumb, 300));
    check(`other pose not mistaken: ${name}`, fp <= 0.05, `${(fp * 100).toFixed(1)}%`);
  }
  const held = new S.SignWatcher({ enabled: [], customs: [model] });
  const longHold = play(held, [[700, OPEN, OPEN, "out"], [1400, PEACE, PEACE, "tucked"], [600, OPEN, OPEN, "out"]], r);
  check("held sign triggers once", longHold.length === 1 && longHold[0].name === "Peace", JSON.stringify(longHold.map((e) => e.name)));
  const flash = new S.SignWatcher({ enabled: [], customs: [model] });
  check("a brief flash of the sign does not trigger", play(flash, [[700, OPEN, OPEN, "out"], [350, PEACE, PEACE, "tucked"], [900, OPEN, OPEN, "out"]], r).length === 0);
  let threw = false;
  try { S.trainSign({ name: "x", kind: "hand", samples: frames(PEACE, "tucked", 3), neutral }); } catch (e) { threw = true; }
  check("too few frames is refused", threw);
  const same = S.trainSign({ name: "Same", kind: "hand", samples: frames(OPEN, "out", 30), neutral: frames(OPEN, "out", 30) });
  check("a sign identical to the normal pose is flagged poor", same.quality === "poor", `separation ${same.separation.toFixed(2)}`);

  const rateOf = (m, vectors) => vectors.filter((v) => S.matchSign([m], v, "hand")).length / vectors.length;
  // Frames caught while the hand moves into the sign must not widen it to in-between poses.
  const moving = [];
  for (let k = 0; k < 8; k++) moving.push(...frames(lerp(OPEN, PEACE, (k + 1) / 9), "out", 1));
  const withMoves = S.trainSign({ name: "Peace", kind: "hand", samples: [...moving.slice(0, 4), ...frames(PEACE, "tucked", 40), ...moving.slice(4)], neutral });
  const between = rateOf(withMoves, frames(lerp(OPEN, PEACE, 0.5), "out", 300));
  check("frames of moving into the sign are left out", between <= 0.05 && withMoves.quality !== "poor", `in-between pose matched ${(between * 100).toFixed(1)}%, quality ${withMoves.quality}`);
  check("...and the sign is still recognised", rateOf(withMoves, frames(PEACE, "tucked", 300)) >= 0.9, `${(rateOf(withMoves, frames(PEACE, "tucked", 300)) * 100).toFixed(1)}%`);

  // Add examples: teach the same sign made a little differently (thumb out instead of tucked);
  // both ways count afterwards, and the stored model stays bounded.
  const before = rateOf(model, frames(PEACE, "out", 300));
  const improved = S.improveSign(model, { samples: frames(PEACE, "out", 40), neutral: frames([0.25, 0.3, 0.3, 0.35], "out", 20) });
  const after = rateOf(improved, frames(PEACE, "out", 300));
  check("add examples: the new way is recognised", after >= 0.9, `${(before * 100).toFixed(1)}% before, ${(after * 100).toFixed(1)}% after`);
  check("add examples: the original way still is", rateOf(improved, frames(PEACE, "tucked", 300)) >= 0.9, `${(rateOf(improved, frames(PEACE, "tucked", 300)) * 100).toFixed(1)}%`);
  const openFp = rateOf(improved, frames(OPEN, "out", 300));
  check("add examples: other poses still not mistaken", openFp <= 0.05 && rateOf(improved, frames(FIST, "wrapped", 300)) <= 0.05, `open ${(openFp * 100).toFixed(1)}%`);
  check("add examples: model stays bounded, same name and kind", improved.pos.length <= 40 && improved.neg.length <= 40 && improved.name === "Peace" && improved.kind === "hand", `${improved.pos.length}+${improved.neg.length} vectors`);

  console.log("testing a taught sign (rehearsal)");
  const rehearse = (script, target = "custom:Peace", extra = {}) => {
    const test = S.makeSignTest(target, "hand", { timeoutMs: 10000 });
    play(new S.SignWatcher({ enabled: [], customs: [model], ...extra }), script, r, { test });
    return test.result;
  };
  const pass = rehearse([[800, OPEN, OPEN, "out"], [1600, PEACE, PEACE, "tucked"], [8000, OPEN, OPEN, "out"]]);
  check("test passes when the sign is made", pass && pass.passed && pass.ms < 3000, pass ? `${pass.passed} after ${Math.round(pass.ms)} ms` : "no result");
  const ordinary = rehearse([[11000, [0.25, 0.3, 0.3, 0.35], [0.25, 0.3, 0.3, 0.35], "out"]]);
  check("test fails, explained, when the sign is never made", ordinary && ordinary.passed === false && /never looked like/.test(ordinary.advice), ordinary && ordinary.advice);
  const away = rehearse([[11000, OPEN, OPEN, "away"]]);
  check("test explains when no hand is in view", away && away.passed === false && /hardly saw your hand/.test(away.advice), away && away.advice);
  const flick = rehearse([[600, OPEN, OPEN, "out"], ...Array.from({ length: 12 }, () => [[300, PEACE, PEACE, "tucked"], [450, OPEN, OPEN, "out"]]).flat(), [2000, OPEN, OPEN, "out"]]);
  check("test explains a sign that is not held long enough", flick && flick.passed === false && /full second/.test(flick.advice), flick && flick.advice);
  const both = rehearse([[600, OPEN, OPEN, "out"], [450, OPEN, OPEN, "tucked"], [300, OPEN, FIST, "tucked"], [600, FIST, FIST, "tucked"], [9000, OPEN, OPEN, "out"]], "custom:Peace", { enabled: ["signal_for_help"] });
  check("test names the sign it saw instead", both && both.passed === false && /Signal for Help/.test(both.advice), both && both.advice);
}

console.log("testing Signal for Help (rehearsal)");
{
  const r = rng(5);
  const rehearse = (script) => {
    const test = S.makeSignTest("signal_for_help", "hand", { timeoutMs: 10000 });
    play(new S.SignWatcher({ enabled: ["signal_for_help"] }), script, r, { test });
    return test.result;
  };
  let passed = 0;
  for (let i = 0; i < 50; i++) {
    const res = rehearse([[uni(r, 500, 3000), OPEN, OPEN, "out"], [500, OPEN, OPEN, "tucked"], [250, OPEN, FIST, "tucked"], [600, FIST, FIST, "tucked"], [7000, OPEN, OPEN, "out"]]);
    passed += res && res.passed ? 1 : 0;
  }
  check("test passes when the Signal for Help is made", passed >= 48, `${passed}/50`);
  const noFold = rehearse([[11000, OPEN, OPEN, "tucked"]]);
  check("test explains a missing fold", noFold && noFold.passed === false && /not the fold/.test(noFold.advice), noFold && noFold.advice);
  const noTuck = rehearse([[11000, OPEN, OPEN, "out"]]);
  check("test explains a missing thumb tuck", noTuck && noTuck.passed === false && /thumb tucked in was not seen/.test(noTuck.advice), noTuck && noTuck.advice);
}

console.log("face");
{
  const r = rng(4);
  const face = (over = {}) => {
    const s = {};
    for (const k of S.FACE_KEYS) s[k] = Math.max(0, uni(r, 0, 0.08) + gauss(r) * 0.02);
    for (const [k, v] of Object.entries(over)) s[k] = Math.min(1, Math.max(0, v + gauss(r) * 0.05));
    return Object.entries(s).map(([categoryName, score]) => ({ categoryName, score }));
  };
  const run = (watcher, script) => {
    const ev = [];
    let t = 0;
    for (const [ms, over] of script) {
      for (let k = 0; k < Math.round(ms / 33); k++) {
        t += 33;
        ev.push(...watcher.update({ t, aspect: 4 / 3, hands: [], face: face(over) }).events);
      }
    }
    return ev;
  };
  const L = { eyeBlinkLeft: 0.85, eyeBlinkRight: 0.08 };
  const R = { eyeBlinkLeft: 0.08, eyeBlinkRight: 0.85 };
  const BLINK = { eyeBlinkLeft: 0.9, eyeBlinkRight: 0.9 };
  let winks = 0;
  for (let i = 0; i < 100; i++) {
    const order = i % 2 ? [L, R] : [R, L];
    winks += run(new S.SignWatcher({ enabled: ["double_wink"] }), [[500, {}], [uni(r, 150, 400), order[0]], [uni(r, 100, 900), {}], [uni(r, 150, 400), order[1]], [500, {}]]).length === 1;
  }
  check("wink then the other eye detected (either order)", winks >= 97, `${winks}/100`);
  let falseWinks = 0;
  for (let i = 0; i < 100; i++) {
    const script = [];
    for (let b = 0; b < 8; b++) script.push([uni(r, 1500, 4000), {}], [uni(r, 100, 200), BLINK]);
    script.push([300, L], [2500, {}], [300, R]);
    falseWinks += run(new S.SignWatcher({ enabled: ["double_wink"] }), script).length;
  }
  check("natural blinks and slow single winks do not trigger", falseWinks === 0, `${falseWinks} false triggers`);

  const vec = (over, n) => Array.from({ length: n }, () => S.faceFeatures(S.faceScores(face(over))));
  const PUFF = { cheekPuff: 0.8, mouthPucker: 0.5 };
  const model = S.trainSign({ name: "Puffed cheeks", kind: "face", samples: vec(PUFF, 40), neutral: vec({}, 40) });
  const hit = vec(PUFF, 300).filter((v) => S.matchSign([model], v, "face")).length / 300;
  const smile = vec({ mouthSmileLeft: 0.8, mouthSmileRight: 0.8 }, 300).filter((v) => S.matchSign([model], v, "face")).length / 300;
  const open = vec({ jawOpen: 0.7 }, 300).filter((v) => S.matchSign([model], v, "face")).length / 300;
  check("custom expression recognised", hit >= 0.9, `${(hit * 100).toFixed(1)}%`);
  check("other expressions not mistaken (smile, open mouth)", smile <= 0.05 && open <= 0.05, `${(smile * 100).toFixed(1)}%, ${(open * 100).toFixed(1)}%`);
}

console.log(failures ? `${failures} check(s) failed` : "all sign checks passed");
process.exit(failures ? 1 : 0);
