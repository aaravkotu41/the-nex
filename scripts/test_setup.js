#!/usr/bin/env node
// Tests for the setup checklist in ui/setup.js: which rows exist, which count, and that it never
// says "all set" unless the service is running now. Run: node scripts/test_setup.js
"use strict";
const assert = require("assert");
const path = require("path");
const S = require(path.join(__dirname, "..", "ui", "setup.js"));

const good = () => ({
  platform: "macos", daemon: { online: true }, service_installed: true, full_disk_access: true,
  dry_run: false, known_bad: { loaded: false, entries: 0 }, canaries: [{}, {}], canaries_intact: 2,
  engine_path: "/Library/Application Support/TheNex/engine/the-nex",
});
const row = (model, id) => model.rows.find((r) => r.id === id);
const states = (model) => Object.fromEntries(model.rows.map((r) => [r.id, r.state]));

// Everything in place: all set, and the list is shown but is not the user's task.
let m = S.checklist(good());
assert.deepStrictEqual(states(m), { service: "ok", disk: "ok", protection: "ok", list: "info", decoys: "ok" });
assert.deepStrictEqual([m.done, m.total, m.allSet], [4, 4, true]);
assert.match(row(m, "list").text, /No list ships yet/);
assert.strictEqual(row(m, "list").pill, "Not available yet");
assert.ok(S.checklist({ ...good(), known_bad: { loaded: true, entries: 1200 } }).rows.find((r) => r.id === "list").text.includes("1,200"));

// Windows has no Full Disk Access row and nothing counts it.
m = S.checklist({ ...good(), platform: "windows", full_disk_access: null });
assert.ok(!row(m, "disk"));
assert.deepStrictEqual([m.done, m.total, m.allSet], [3, 3, true]);

// Service stopped or its status stale (the app sees both as offline): never "all set", and what
// only the service can tell is unknown, not guessed.
m = S.checklist({ ...good(), daemon: { online: false } });
assert.strictEqual(m.allSet, false);
assert.strictEqual(row(m, "service").state, "todo");
assert.strictEqual(row(m, "service").action.label, "Reinstall service");
assert.strictEqual(row(m, "disk").state, "unknown");
assert.strictEqual(row(m, "protection").state, "unknown");
assert.deepStrictEqual([m.done, m.total], [1, 4]); // only the decoys
assert.strictEqual(S.checklist({ ...good(), daemon: { online: false }, service_installed: false }).rows[0].action.label, "Install service");
assert.strictEqual(row(S.checklist({ ...good(), service_installed: false }), "service").state, "todo");

// Full Disk Access: denied, not reported yet (older service), and granted.
m = S.checklist({ ...good(), full_disk_access: false });
assert.strictEqual(row(m, "disk").state, "todo");
assert.strictEqual(row(m, "disk").action.id, "open_disk_settings");
assert.strictEqual(row(m, "disk").engine_path, "/Library/Application Support/TheNex/engine/the-nex");
assert.match(row(m, "disk").note, /updated/);
assert.strictEqual(m.allSet, false);
for (const unreported of [null, undefined]) {
  m = S.checklist({ ...good(), full_disk_access: unreported });
  assert.strictEqual(row(m, "disk").state, "unknown");
  assert.strictEqual(m.allSet, false);
}
assert.strictEqual(row(S.checklist(good()), "disk").engine_path, undefined);

// Dry Run is explained and has its own button; decoys offer create or repair.
m = S.checklist({ ...good(), dry_run: true });
assert.strictEqual(row(m, "protection").state, "todo");
assert.match(row(m, "protection").text, /Dry Run is on.*nothing is moved or stopped/);
assert.strictEqual(row(m, "protection").action.id, "dry_run_off");
assert.strictEqual(row(S.checklist({ ...good(), canaries: [], canaries_intact: 0 }), "decoys").action.label, "Create decoy files");
m = S.checklist({ ...good(), canaries_intact: 1 });
assert.strictEqual(row(m, "decoys").text, "1 of 2 decoy files are in place.");
assert.strictEqual(row(m, "decoys").action.label, "Repair decoy files");

// Odd input does not throw.
assert.doesNotThrow(() => S.checklist({ daemon: {}, canaries: null }));
console.log("setup checklist tests passed");
