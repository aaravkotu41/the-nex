// Plain-English lines for the Scheduled scan row in Settings. Pure, so scripts/test_summary.js
// can check them without a window.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.NexSummary = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const DAY_MS = 86400000;
  const INTERVAL = { daily: DAY_MS, weekly: 7 * DAY_MS };

  /** When the next scan is due, in words. `now` is a Date; `fmt` turns a Date into text. */
  function nextRunText(info, online, now, fmt) {
    const interval = INTERVAL[info && info.schedule];
    if (!interval) return "Off. The Nex only scans when you ask it to.";
    if (!online) return "On, but the background service is not running, so no scan will start until it is.";
    const last = info.last_run ? new Date(info.last_run) : null;
    // A last run in the future means the clock was set back: the service starts over from now.
    if (!last || Number.isNaN(last.getTime()) || last > now) {
      return "The first scan starts about 10 minutes after you switch this on or the service starts.";
    }
    const due = new Date(last.getTime() + interval);
    return due <= now ? "A scan is due now and should start within a few minutes." : `Next scan: around ${fmt(due)}.`;
  }

  /** The last scheduled scan's result, in words. */
  function lastScanText(info, fmt) {
    const scan = info && info.last_scan;
    if (!scan) return "No scheduled scan has run yet.";
    const when = scan.finished_at ? fmt(new Date(scan.finished_at)) : "an unknown time";
    const checked = `${scan.files_examined} file${scan.files_examined === 1 ? "" : "s"} looked at`;
    const found = scan.findings
      ? `${scan.findings} flagged (nothing was moved or deleted)`
      : "nothing suspicious found";
    const notes = [
      scan.cancelled ? "stopped early" : "",
      scan.truncated ? "hit its file limit" : "",
      scan.unreadable ? `${scan.unreadable} folder${scan.unreadable === 1 ? "" : "s"} could not be opened` : "",
      scan.cloud_skipped ? `${scan.cloud_skipped} cloud-only file${scan.cloud_skipped === 1 ? "" : "s"} skipped (reading them would download them)` : "",
    ].filter(Boolean);
    return `Last scheduled scan, ${when}: ${checked}, ${found}${notes.length ? `; ${notes.join("; ")}` : ""}.`;
  }

  return { nextRunText, lastScanText };
});
