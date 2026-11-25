// "Startup": what starts by itself on this computer, and what The Nex makes of each item.
// The check is one button with no arguments (crates/the-nex-gui/src/startup.rs): this page can
// not choose what is read. The engine only reads, and the result stays in this page's memory.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.NexStartup = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const KINDS = {
    launch_daemon: "Background service (launch daemon)",
    launch_agent: "Starts when you log in (launch agent)",
    cron: "Scheduled job (cron)",
    run_key: "Starts when you log in (Run key)",
    run_once_key: "Starts once at next log in (RunOnce key)",
    startup_folder: "Startup folder",
  };
  const RUNS_AS = { you: "You (your account)", system: "The system (every user, full rights)", "every user": "Whichever user logs in" };
  const VERDICTS = ["suspicious", "worth_a_look", "not_checked", "nothing_found"];
  const LIMITS = "This is a quick look, not a guarantee. Some malware gets past checks like this.";
  const UNCHANGED = "The Nex only looks. Nothing here is turned off, moved, deleted or sent anywhere.";

  /** `table[key]`, own entries only: a key comes from a file anyone can write ("constructor"). */
  const lookup = (table, key) => (Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined);

  /** The pill for a verdict. Never says "safe" and is never green: the best answer is only that
   *  the program file showed no warning signs. */
  function pillFor(verdict) {
    if (verdict === "suspicious") return { tone: "red", pill: "Suspicious" };
    if (verdict === "worth_a_look") return { tone: "amber", pill: "Worth a look" };
    if (verdict === "nothing_found") return { tone: "gray", pill: "No warning signs" };
    return { tone: "gray", pill: "Not checked" };
  }

  /** What to show for one item: plain strings only (names come from files anyone can write). */
  function present(item) {
    const r = item || {};
    const { tone, pill } = pillFor(r.verdict);
    const reasons = (Array.isArray(r.reasons) ? r.reasons : []).map(String);
    if (r.verdict === "nothing_found") reasons.push(LIMITS);
    const facts = [["Set up in", String(r.location || "unknown"), r.location ? String(r.location) : ""]];
    facts.push(r.program ? ["Program", String(r.program), String(r.program)] : ["Program", "not known"]);
    const args = Array.isArray(r.arguments) ? r.arguments : [];
    if (args.length) facts.push(["Arguments", args.join(" ")]);
    if (r.script) facts.push(["Script it runs", String(r.script), String(r.script)]);
    facts.push(["Runs as", lookup(RUNS_AS, r.runs_as) || String(r.runs_as || "unknown")]);
    if (r.enabled === true) facts.push(["Turned on", "Yes, it starts by itself"]);
    if (r.enabled === false) facts.push(["Turned on", "No, its file says it is turned off"]);
    if (r.program) {
      facts.push(["Program found", r.exists ? "Yes" : r.exists === false ? "No" : "Not known"]);
      if (r.exists) facts.push(["Signed by a trusted publisher", r.trusted ? "Yes" : "No"]);
    }
    if (Number.isFinite(r.score)) facts.push(["Program score", r.score.toFixed(2)]);
    if (r.allowed) facts.push(["Always allowed", "Yes, you chose this exact file"]);
    return {
      name: String(r.name || "unnamed"),
      kind: lookup(KINDS, r.kind) || "Startup item",
      tone, pill, reasons, facts,
      verdict: VERDICTS.includes(r.verdict) ? r.verdict : "not_checked",
      runsAs: String(r.runs_as || "unknown"),
    };
  }

  /** Counts per verdict, and the items with the most worrying first (the engine sorts too). */
  function summarize(report) {
    const items = Array.isArray(report && report.items) ? report.items.slice() : [];
    const rank = (i) => { const n = VERDICTS.indexOf(i && i.verdict); return n < 0 ? VERDICTS.length : n; };
    items.sort((a, b) => rank(a) - rank(b));
    const counts = { all: items.length };
    for (const v of VERDICTS) counts[v] = items.filter((i) => rank(i) === VERDICTS.indexOf(v)).length;
    return { items, counts };
  }

  function status(report) {
    const { counts } = summarize(report);
    const parts = [counts.all === 1 ? "Checked 1 startup item." : `Checked ${counts.all} startup items.`];
    if (report.truncated) parts.push("Not everything could be listed or checked, because there was too much or the time ran out.");
    parts.push(UNCHANGED);
    return parts.join(" ");
  }

  /** Wires the page. `deps` is the app's own helpers: call, el, expandable, detailGrid, chevron, errorText. */
  function start(deps) {
    const $ = (id) => document.getElementById(id);
    const button = $("startup-check");
    if (!button || !deps || !deps.call) return;
    const { el, expandable, detailGrid, chevron } = deps;
    const state = { report: null, filter: "all", open: null };

    function render() {
      const { items, counts } = summarize(state.report);
      $("startup-tiles").hidden = false;
      for (const tile of document.querySelectorAll("#startup-tiles .pill-filter")) {
        const key = tile.dataset.filter;
        $(`startup-count-${key}`).textContent = String(counts[key]);
        tile.classList.toggle("active", key === state.filter);
        tile.setAttribute("aria-pressed", String(key === state.filter));
      }
      $("startup-status").textContent = status(state.report);
      const shown = items.filter((i) => state.filter === "all" || i.verdict === state.filter);
      const rows = [];
      for (const item of shown) {
        const view = present(item);
        const key = `${item.kind}|${item.location}|${item.name}`;
        const open = state.open === key;
        const cells = [
          el("td", { title: view.name }, [
            el("span", { className: "cell-main", text: view.name }),
            el("span", { className: "cell-sub", text: String(item.location || "") }),
          ]),
          el("td", { className: "sans", text: view.kind }),
          el("td", { className: "sans" }, [el("span", { className: `pill status ${view.tone}`, text: view.pill })]),
          el("td", { className: "sans", text: view.runsAs === "system" ? "System" : view.runsAs === "you" ? "You" : view.runsAs }),
          el("td", {}, [chevron()]),
        ];
        const detail = el("div", {}, view.reasons.map((r) => el("p", { className: "check-line", text: r })));
        detail.append(detailGrid(view.facts, ""));
        rows.push(...expandable(cells, detail, open, () => { state.open = open ? null : key; render(); }, 5));
      }
      $("startup-rows").replaceChildren(...rows);
      $("startup-table").hidden = shown.length === 0;
      $("startup-empty").hidden = shown.length > 0;
      const places = state.report.unreadable || [];
      $("startup-unreadable").hidden = places.length === 0;
      $("startup-unreadable-list").replaceChildren(...places.map((p) => el("li", {}, [
        el("b", { className: "mono", text: String(p.place) }),
        el("span", { className: "muted", text: ` ${String(p.reason)}` }),
      ])));
    }

    for (const tile of document.querySelectorAll("#startup-tiles .pill-filter")) {
      tile.addEventListener("click", () => { state.filter = tile.dataset.filter; if (state.report) render(); });
    }
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Checking…";
      $("startup-status").textContent = "Looking at what starts by itself. This can take up to a minute.";
      try {
        state.report = await deps.call("check_startup");
        state.open = null;
        render();
      } catch (error) {
        $("startup-status").textContent = deps.errorText(error);
      }
      button.disabled = false;
      button.textContent = "Check again";
    });
  }

  return { present, summarize, status, start, UNCHANGED };
});
