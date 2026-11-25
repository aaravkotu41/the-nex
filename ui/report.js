// Text for a problem report. The app never sends it: "Report as safe" copies it to the
// clipboard and opens the website's form, where the person reads it, pastes it and presses Send.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.NexReport = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /** Replaces the account name in home-folder paths (C:\Users\name\, /Users/name/, /home/name/).
   *  Greedy up to the next separator, so a name with spaces is removed whole. */
  function scrub(text) {
    return String(text || "").replace(/((?:[A-Za-z]:)?[\\/](?:Users|home)[\\/])[^\\/"'<>|:*?\r\n]+/gi, "$1…");
  }

  function fileName(path) {
    const parts = String(path || "").split(/[\\/]/).filter(Boolean);
    return parts.length ? parts[parts.length - 1] : "";
  }

  /** The copied details for one Activity event or quarantined file: its name, never its folder. */
  function reportText(item, app) {
    return [
      `App: The Nex ${app.version || "?"} on ${app.platform || "?"}`,
      `Type: ${item.threat_type || "?"}`,
      item.severity ? `Severity: ${item.severity}` : null,
      `File: ${fileName(item.target)}`,
      item.sha256 ? `SHA-256: ${item.sha256}` : null,
      item.size ? `Size: ${item.size} bytes` : null,
      `Why: ${scrub(item.details)}`,
      item.action_taken ? `Action: ${scrub(item.action_taken)}` : null,
      item.timestamp ? `When: ${item.timestamp}` : null,
    ].filter(Boolean).join("\n");
  }

  return { scrub, fileName, reportText };
});
