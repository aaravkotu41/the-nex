#!/usr/bin/env node
// Tests for ui/startup.js: how a startup item is worded. Nothing is ever called "safe", every
// text from a file stays plain text, and odd or missing fields never break the page.
// Run: node scripts/test_startup.js  (exit 1 on failure)
"use strict";
const assert = require("assert");
const path = require("path");
const S = require(path.join(__dirname, "..", "ui", "startup.js"));

const base = { name: "com.example.agent", kind: "launch_agent", location: "/Library/LaunchAgents/a.plist", program: "/opt/a", arguments: ["-x", "y z"], script: null, enabled: true, exists: true, trusted: true, verdict: "nothing_found", score: null, reasons: [], allowed: false, runs_as: "you" };

const fine = S.present(base);
assert.strictEqual(fine.pill, "Nothing suspicious found");
assert.strictEqual(fine.tone, "green");
assert.ok(fine.reasons.some((r) => /not a guarantee/.test(r)), "the limits are stated");
assert.ok(!/\bsafe\b/i.test(JSON.stringify(fine)), "never says safe");
assert.deepStrictEqual(fine.facts.find(([k]) => k === "Arguments"), ["Arguments", "-x y z"]);
assert.ok(fine.facts.some(([k, v]) => k === "Signed by a trusted publisher" && v === "Yes"));
assert.ok(fine.facts.some(([k, v]) => k === "Runs as" && /You/.test(v)));
assert.ok(fine.facts.some(([k, , copy]) => k === "Program" && copy === "/opt/a"), "the path can be copied");

const bad = S.present({ ...base, verdict: "suspicious", trusted: false, score: 0.93, reasons: ["Its name says it comes from Apple, but it is not."], runs_as: "system" });
assert.deepStrictEqual([bad.tone, bad.pill], ["red", "Suspicious"]);
assert.strictEqual(bad.reasons[0], "Its name says it comes from Apple, but it is not.");
assert.ok(bad.facts.some(([k, v]) => k === "Program score" && v === "0.93"));
assert.ok(bad.facts.some(([k, v]) => k === "Signed by a trusted publisher" && v === "No"));
assert.ok(bad.facts.some(([k, v]) => k === "Runs as" && /system/i.test(v)));

const look = S.present({ ...base, verdict: "worth_a_look", exists: false, enabled: false, script: "/tmp/x.sh", allowed: true });
assert.deepStrictEqual([look.tone, look.pill], ["amber", "Worth a look"]);
assert.ok(look.facts.some(([k, v]) => k === "Program found" && v === "No"));
assert.ok(!look.facts.some(([k]) => k === "Signed by a trusted publisher"), "no signature question for a missing file");
assert.ok(look.facts.some(([k, v]) => k === "Turned on" && /turned off/.test(v)));
assert.ok(look.facts.some(([k, , c]) => k === "Script it runs" && c === "/tmp/x.sh"));
assert.ok(look.facts.some(([k]) => k === "Always allowed"));

// Hostile text stays text, and a broken or empty item still shows.
const odd = S.present({ name: "<img src=x onerror=alert(1)>", verdict: "weird", reasons: null, arguments: "no", kind: "nope", runs_as: "someone" });
assert.strictEqual(odd.name, "<img src=x onerror=alert(1)>");
assert.deepStrictEqual([odd.tone, odd.pill, odd.verdict], ["gray", "Not checked", "not_checked"]);
assert.strictEqual(odd.kind, "Startup item");
assert.ok(odd.facts.some(([k, v]) => k === "Program" && v === "not known"));
assert.ok(S.present(null).name && S.present(undefined).pill);

// Counts and order: the most worrying first, whatever order the engine used.
const report = { items: [{ ...base, verdict: "nothing_found" }, { ...base, verdict: "not_checked" }, { ...base, verdict: "suspicious" }, { ...base, verdict: "worth_a_look" }, { ...base, verdict: "nothing_found" }], unreadable: [], skipped: 2, truncated: false };
const sum = S.summarize(report);
assert.deepStrictEqual(sum.items.map((i) => i.verdict), ["suspicious", "worth_a_look", "nothing_found", "nothing_found", "not_checked"]);
assert.deepStrictEqual(sum.counts, { all: 5, suspicious: 1, worth_a_look: 1, nothing_found: 2, not_checked: 1 });
assert.strictEqual(S.summarize(null).counts.all, 0);
assert.strictEqual(S.summarize({ items: "x" }).counts.all, 0);

// The status line says what was left out and that nothing was changed.
const line = S.status(report);
assert.ok(/Checked 5 startup items/.test(line) && /2 that belong to the operating system were left out/.test(line));
assert.ok(line.includes(S.UNCHANGED) && /nothing|Nothing/.test(S.UNCHANGED));
assert.ok(/Checked 1 startup item\./.test(S.status({ items: [base], skipped: 0 })));
assert.ok(/more than can be listed/.test(S.status({ items: [], truncated: true })));

console.log("startup.js: all checks passed");
