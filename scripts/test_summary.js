#!/usr/bin/env node
// Tests for the Scheduled scan wording in ui/summary.js. Run: node scripts/test_summary.js
"use strict";
const assert = require("assert");
const path = require("path");
const S = require(path.join(__dirname, "..", "ui", "summary.js"));

const now = new Date("2026-11-25T12:00:00Z");
const fmt = (d) => d.toISOString().slice(0, 16);
const next = (info, online = true) => S.nextRunText(info, online, now, fmt);

assert.match(next({ schedule: "off" }), /^Off\./);
assert.match(next({ schedule: "off", last_run: "2026-11-24T12:00:00Z" }), /^Off\./);
assert.match(next({ schedule: "hourly" }), /^Off\./); // an unknown value is off, as in the service
assert.match(next(null), /^Off\./);
assert.match(next({ schedule: "daily" }, false), /not running/);
assert.match(next({ schedule: "daily" }), /first scan starts about 10 minutes/);
assert.match(next({ schedule: "daily", last_run: "not a date" }), /first scan/);
assert.match(next({ schedule: "daily", last_run: "2026-12-30T00:00:00Z" }), /first scan/); // clock set back
assert.strictEqual(next({ schedule: "daily", last_run: "2026-11-25T06:00:00Z" }), "Next scan: around 2026-11-26T06:00.");
assert.strictEqual(next({ schedule: "weekly", last_run: "2026-11-24T12:00:00Z" }), "Next scan: around 2026-12-01T12:00.");
// Exactly one interval ago is due; a second earlier is not.
assert.match(next({ schedule: "daily", last_run: "2026-11-24T12:00:00Z" }), /due now/);
assert.match(next({ schedule: "daily", last_run: "2026-11-24T12:00:01Z" }), /^Next scan/);

assert.strictEqual(S.lastScanText(null, fmt), "No scheduled scan has run yet.");
assert.strictEqual(S.lastScanText({ last_scan: null }, fmt), "No scheduled scan has run yet.");
const scan = { finished_at: "2026-11-25T10:00:00Z", files_examined: 1, findings: 0, unreadable: 0, cancelled: false, truncated: false };
assert.strictEqual(S.lastScanText({ last_scan: scan }, fmt), "Last scheduled scan, 2026-11-25T10:00: 1 file looked at, nothing suspicious found.");
const worse = S.lastScanText({ last_scan: { ...scan, files_examined: 2500, findings: 2, unreadable: 1, cancelled: true } }, fmt);
assert.ok(worse.includes("2500 files looked at, 2 flagged (nothing was moved or deleted); stopped early; 1 folder could not be opened."), worse);
assert.ok(!/undefined|NaN|null/.test(worse));
const cloud = S.lastScanText({ last_scan: { ...scan, cloud_skipped: 3 } }, fmt);
assert.ok(cloud.endsWith("nothing suspicious found; 3 cloud-only files skipped (reading them would download them)."), cloud);
assert.ok(S.lastScanText({ last_scan: { ...scan, cloud_skipped: 1 } }, fmt).includes("1 cloud-only file skipped"));
assert.ok(!S.lastScanText({ last_scan: { ...scan, cloud_skipped: 0 } }, fmt).includes("cloud"));
console.log("scheduled scan wording tests passed");
