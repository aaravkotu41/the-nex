#!/usr/bin/env node
// Tests for ui/filecheck.js: what a file-check result says. A clean result must never claim a
// file is "safe", and every other kind of file must say plainly why nothing was scored.
// Run: node scripts/test_filecheck.js  (exit 1 on failure)
"use strict";
const assert = require("assert");
const path = require("path");
const C = require(path.join(__dirname, "..", "ui", "filecheck.js"));

const base = { name: "setup.exe", size: 2048, sha256: "ab".repeat(32), reasons: [], checks: ["program"] };

const bad = C.present({ ...base, verdict: "suspicious", score: 0.93, threshold: 0.65, reasons: ["Its code looks scrambled."] });
assert.strictEqual(bad.tone, "red");
assert.strictEqual(bad.pill, "Suspicious");
assert.ok(bad.lines[0].includes("0.93") && bad.lines[0].includes("0.65"), bad.lines[0]);
assert.ok(bad.lines.includes("Its code looks scrambled."));

const fine = C.present({ ...base, verdict: "nothing_found", score: 0.1, threshold: 0.65 });
assert.strictEqual(fine.tone, "green");
assert.strictEqual(fine.pill, "Nothing suspicious found");
assert.ok(fine.lines.some((l) => /not a guarantee/.test(l)), "the limits are stated");
assert.ok(fine.facts.some(([k, v]) => k === "Known-malware list" && /none installed/.test(v)));

const other = C.present({ ...base, verdict: "not_scanned", checks: [], reasons: ["This is not a program or archive, so there is nothing to score."] });
assert.strictEqual(other.pill, "Nothing to score");
assert.ok(other.lines[0].includes("nothing to score"));
assert.strictEqual(other.tone, "gray");

const partly = C.present({ ...base, verdict: "partly_checked", checks: ["archive"], reasons: ["The check stopped early."] });
assert.strictEqual(partly.tone, "amber");
assert.strictEqual(partly.pill, "Not fully checked");
assert.ok(!partly.lines.some((l) => /not a guarantee/.test(l)) || partly.tone !== "green");

const signed = C.present({ ...base, verdict: "nothing_found", checks: ["signature"], reasons: ["It was trusted because it carries a signature."] });
const checksRun = signed.facts.find(([k]) => k === "Checks run")[1];
assert.ok(/Signature check/.test(checksRun) && !/AI score/.test(checksRun), checksRun);

const refused = C.present({ name: "Docs", verdict: "refused", size: null, sha256: null, reasons: ["That is a folder."], checks: [] });
assert.strictEqual(refused.tone, "amber");
assert.strictEqual(refused.pill, "Not checked");
assert.deepStrictEqual(refused.facts, []);
assert.strictEqual(refused.sha256, "");

// Nothing a result can say includes the word "safe", and a score never shows for a refusal.
const everything = [bad, fine, other, partly, signed, refused].map((v) => JSON.stringify(v)).join(" ");
assert.ok(!/\bsafe\b/i.test(everything), everything);
assert.ok(!C.present({ verdict: "refused", score: 0.9, threshold: 0.6, reasons: [], checks: [] }).lines.some((l) => /score/i.test(l)));

// Odd input never throws; a file name stays plain text for the page to put in with textContent.
assert.doesNotThrow(() => C.present(null));
assert.doesNotThrow(() => C.present({ verdict: "weird", reasons: "no", checks: 7 }));
assert.strictEqual(C.present({ name: "<img src=x onerror=1>.zip", verdict: "refused" }).name, "<img src=x onerror=1>.zip");

assert.strictEqual(C.size(500), "500 bytes");
assert.strictEqual(C.size(1536), "1.5 KB");
assert.strictEqual(C.size(5 * 1024 * 1024), "5.0 MB");
assert.strictEqual(C.size(300 * 1024 * 1024), "300 MB");
console.log("file check tests passed");
