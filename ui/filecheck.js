// "Check a file": drop files on the window and see what The Nex's engines make of them.
// The drop itself is handled by the app (crates/the-nex-gui/src/filecheck.rs), which sends the
// result as an event; this page never passes a path to anything and has no command to call, so
// nothing here (or in a synced command) can point the check at a file the user did not drop.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.NexFileCheck = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const CHECK_NAMES = { program: "Program check (AI score)", archive: "Archive check (zip bombs)", list: "Known-malware list" };
  const LIMITS = "This is a quick look at how the file is built, not a guarantee. Some malware gets past checks like this.";
  const RESULT_EVENT = "filecheck://result";

  function size(bytes) {
    if (!Number.isFinite(bytes)) return "";
    if (bytes < 1024) return `${bytes} bytes`;
    const units = ["KB", "MB", "GB"];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
  }

  /** What to show for one result: a tone for the pill, its words, and plain lines of detail.
   *  Never says a file is "safe": the best answer is that nothing suspicious was found. */
  function present(result) {
    const r = result || {};
    const checks = Array.isArray(r.checks) ? r.checks : [];
    const lines = [];
    if (r.verdict !== "refused" && Number.isFinite(r.score) && Number.isFinite(r.threshold)) {
      lines.push(`Program score ${r.score.toFixed(2)}. The Nex acts at ${r.threshold.toFixed(2)} and above.`);
    }
    for (const reason of Array.isArray(r.reasons) ? r.reasons : []) lines.push(String(reason));
    let tone = "gray";
    let pill = "Not checked";
    if (r.verdict === "suspicious") { tone = "red"; pill = "Suspicious"; }
    else if (r.verdict === "nothing_found") { tone = "green"; pill = "Nothing suspicious found"; lines.push(LIMITS); }
    else if (r.verdict === "not_scanned") { pill = "Nothing to score"; }
    else if (r.verdict === "refused") { tone = "amber"; }
    const facts = [];
    if (Number.isFinite(r.size)) facts.push(["Size", size(r.size)]);
    if (r.verdict !== "refused") {
      facts.push(["Checks run", checks.length ? checks.map((c) => CHECK_NAMES[c] || c).join(", ") : "none"]);
      if (!checks.includes("list")) facts.push(["Known-malware list", "none installed, so it was not used"]);
    }
    return { name: String(r.name || "file"), tone, pill, lines, facts, sha256: typeof r.sha256 === "string" ? r.sha256 : "" };
  }

  /** Wires the drop overlay and result panel. `copyButton(text, label)` is the app's own. */
  function start(copyButton) {
    const events = window.__TAURI__ && window.__TAURI__.event;
    const $ = (id) => document.getElementById(id);
    const panel = $("check-panel");
    if (!events || !panel) return;
    const overlay = $("drop-overlay");
    const status = $("check-status");
    const list = $("check-list");
    const hide = () => { panel.hidden = true; };
    $("check-dismiss").addEventListener("click", hide);
    panel.addEventListener("keydown", (event) => { if (event.key === "Escape") hide(); });

    function render(outcome) {
      list.replaceChildren();
      const results = (outcome && outcome.results) || [];
      status.textContent = outcome && outcome.error ? outcome.error
        : results.length === 1 ? "Checked 1 file." : `Checked ${results.length} files.`;
      for (const result of results) {
        const view = present(result);
        const item = document.createElement("li");
        item.className = "check-item";
        const head = document.createElement("div");
        head.className = "check-head";
        const name = document.createElement("b");
        name.className = "check-name";
        name.textContent = view.name; // a file name is untrusted text: never markup
        name.title = view.name;
        const pill = document.createElement("span");
        pill.className = `pill status ${view.tone}`;
        pill.textContent = view.pill;
        head.append(name, pill);
        item.append(head);
        for (const line of view.lines) {
          const p = document.createElement("p");
          p.className = "check-line";
          p.textContent = line;
          item.append(p);
        }
        const facts = document.createElement("dl");
        facts.className = "check-facts";
        for (const [term, value] of view.facts) {
          const dt = document.createElement("dt");
          dt.textContent = term;
          const dd = document.createElement("dd");
          dd.textContent = value;
          facts.append(dt, dd);
        }
        if (view.sha256) {
          const dt = document.createElement("dt");
          dt.textContent = "SHA-256";
          const dd = document.createElement("dd");
          const hash = document.createElement("span");
          hash.className = "mono";
          hash.textContent = `${view.sha256.slice(0, 16)}…`;
          dd.append(hash, " ", copyButton(view.sha256));
          facts.append(dt, dd);
        }
        item.append(facts);
        list.append(item);
      }
      panel.hidden = false;
    }

    // Only a drag that carries files shows the overlay (selected text has no paths).
    events.listen("tauri://drag-enter", (e) => { overlay.hidden = !(e.payload && e.payload.paths && e.payload.paths.length); });
    events.listen("tauri://drag-leave", () => { overlay.hidden = true; });
    events.listen("tauri://drag-drop", (e) => {
      overlay.hidden = true;
      const n = e.payload && e.payload.paths ? e.payload.paths.length : 0;
      if (!n) return;
      list.replaceChildren();
      status.textContent = n === 1 ? "Checking 1 file…" : `Checking ${n} files…`;
      panel.hidden = false;
    });
    events.listen(RESULT_EVENT, (e) => render(e.payload));
  }

  return { present, size, start };
});
