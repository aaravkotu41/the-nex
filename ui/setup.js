// The setup checklist (Settings, and a one-line hint on Overview while something is missing).
// `checklist` is a pure function of the dashboard state so it can be tested without a window.
// It never says "all set" unless the service is running now: a stopped or stale service means
// nothing is being checked, and what only the service can report is shown as unknown.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.NexSetup = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const UPDATE_NOTE = "After The Nex is updated, macOS may ask for this again: switch it off and on once more.";

  const ENGINES = [
    ["known_bad_enabled", "Known Malware List"], ["zip_bomb_enabled", "Zip Bomb Guard"], ["bin_ai_enabled", "ONNX Binary AI"],
    ["process_guard_enabled", "LotL Process Guard"], ["canary_enabled", "Canary Honeypots"],
  ];

  /** states: ok (done), todo (needs you), unknown (cannot tell), info (shown, never counted). */
  function checklist(d) {
    const online = Boolean(d.daemon && d.daemon.online);
    const installed = Boolean(d.service_installed);
    const rows = [];

    rows.push(online && installed
      ? { id: "service", title: "Background service", state: "ok", text: "The background service is installed and running." }
      : {
        id: "service", title: "Background service", state: "todo",
        text: online
          ? "The engine is running, but not as an installed service, so it stops when you close it."
          : installed
            ? "The service is installed but not responding, so nothing is being checked right now. Reinstalling usually fixes it."
            : "The background service is not installed, so nothing is being checked.",
        action: { id: "install", label: installed ? "Reinstall service" : "Install service" },
      });

    if (d.platform === "macos") {
      const access = d.full_disk_access;
      const row = { id: "disk", title: "Full Disk Access" };
      if (!online) {
        Object.assign(row, { state: "unknown", text: "Cannot tell while the service is not running." });
      } else if (access === true) {
        Object.assign(row, { state: "ok", text: "The service can read your Desktop, Documents and Downloads." });
      } else {
        const open = { id: "open_disk_settings", label: "Open System Settings" };
        Object.assign(row, access === false
          ? { state: "todo", text: "macOS is hiding Desktop, Documents and Downloads from the service, so files there are not checked. Add the program below in System Settings and switch it on.", action: open }
          : { state: "unknown", text: "The service has not reported this yet. If it stays unknown, restart the service.", action: open });
        row.engine_path = d.engine_path || "";
        row.note = UPDATE_NOTE;
      }
      rows.push(row);
    }

    // An engine that is switched off protects nothing; the known-malware list only counts once a list is loaded.
    const toggles = d.toggles && typeof d.toggles === "object" ? d.toggles : null;
    const listLoaded = Boolean(d.known_bad && d.known_bad.loaded);
    const off = toggles ? ENGINES.filter(([key]) => toggles[key] === false && (key !== "known_bad_enabled" || listLoaded)).map(([, name]) => name) : [];

    const protection = { id: "protection", title: "Protection is on" };
    if (d.dry_run) {
      Object.assign(protection, {
        state: "todo",
        text: "Dry Run is on: threats are noticed and logged, but nothing is moved or stopped. Turn it off to protect for real.",
        action: { id: "dry_run_off", label: "Turn off Dry Run" },
      });
    } else if (!online) {
      Object.assign(protection, { state: "unknown", text: "Dry Run is off, but protection only works while the service is running." });
    } else if (!toggles) {
      Object.assign(protection, { state: "unknown", text: "Dry Run is off, but which checks are switched on could not be read." });
    } else if (off.length) {
      Object.assign(protection, { state: "todo", text: `Switched off: ${off.join(", ")}. Turn ${off.length === 1 ? "it" : "them"} on in Engines, or that protection is missing.` });
    } else {
      Object.assign(protection, { state: "ok", text: "Dry Run is off and every check is on: threats are quarantined or stopped as they appear." });
    }
    rows.push(protection);

    const list = d.known_bad && d.known_bad.loaded ? d.known_bad : null;
    rows.push({
      id: "list", title: "Known-malware list", state: "info", tone: list ? "green" : "gray",
      pill: list ? "Loaded" : "Not available yet",
      text: list
        ? `${Number(list.entries).toLocaleString("en-US")} known threats are checked by fingerprint.`
        : "No list ships yet. That is expected: the other checks work without it.",
    });

    const canaries = Array.isArray(d.canaries) ? d.canaries.length : 0;
    const intact = Number(d.canaries_intact) || 0;
    const watching = !toggles || toggles.canary_enabled !== false;
    rows.push(canaries > 0 && intact === canaries && !watching
      ? { id: "decoys", title: "Decoy files", state: "todo", text: `All ${canaries} decoy files are in place, but Canary Honeypots is switched off, so changes to them are not noticed. Turn it on in Engines.` }
      : canaries > 0 && intact === canaries
      ? { id: "decoys", title: "Decoy files", state: "ok", text: `All ${canaries} decoy files are in place. They reveal ransomware the moment one changes.` }
      : {
        id: "decoys", title: "Decoy files", state: "todo",
        text: canaries === 0
          ? "No decoy files exist yet. They reveal ransomware the moment one changes."
          : `${intact} of ${canaries} decoy files are in place.`,
        action: { id: "decoys", label: canaries === 0 ? "Create decoy files" : "Repair decoy files" },
      });

    const counted = rows.filter((row) => row.state !== "info");
    const done = counted.filter((row) => row.state === "ok").length;
    return { rows, done, total: counted.length, allSet: online && done === counted.length };
  }

  const PILLS = { ok: ["green", "Done"], todo: ["amber", "Needs you"], unknown: ["gray", "Unknown"] };

  /** Builds the panel rows and the Overview hint; actions are carried out by `deps.run(id)`; `deps.copyButton(text)` makes the copy button. */
  let deps = null;
  function start(wanted) {
    deps = wanted;
    const rowsNode = document.getElementById("setup-rows");
    if (!rowsNode) return;
    rowsNode.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-setup-action]");
      if (button && !button.disabled) deps.run(button.dataset.setupAction);
    });
  }

  function render(d) {
    const rowsNode = document.getElementById("setup-rows");
    const summary = document.getElementById("setup-summary");
    const hint = document.getElementById("setup-hint");
    if (!rowsNode || !deps) return;
    const model = d ? checklist(d) : null;
    const signature = JSON.stringify(model);
    if (rowsNode.dataset.signature === signature) return;
    rowsNode.dataset.signature = signature;
    hint.hidden = !model || model.allSet;
    if (!model) {
      summary.className = "pill status";
      summary.textContent = "Unknown";
      rowsNode.replaceChildren(Object.assign(document.createElement("li"), { className: "muted", textContent: "The state of The Nex could not be read." }));
      return;
    }
    summary.className = `pill status ${model.allSet ? "green" : "amber"}`;
    summary.textContent = model.allSet ? "All set" : `${model.done} of ${model.total} set up`;
    document.getElementById("setup-hint-text").textContent = `${model.done} of ${model.total} set up`;
    rowsNode.replaceChildren(...model.rows.map((row) => {
      const [tone, label] = row.state === "info" ? [row.tone, row.pill] : PILLS[row.state];
      const li = document.createElement("li");
      li.className = "setup-row";
      const pill = Object.assign(document.createElement("span"), { className: `pill status ${tone}`, textContent: label });
      const body = document.createElement("div");
      body.append(
        Object.assign(document.createElement("h3"), { textContent: row.title }),
        Object.assign(document.createElement("p"), { className: "muted", textContent: row.text }),
      );
      if (row.engine_path) {
        const path = Object.assign(document.createElement("code"), { className: "path-badge", textContent: row.engine_path });
        const line = document.createElement("p");
        line.className = "setup-path";
        line.append(path, " ", deps.copyButton(row.engine_path));
        body.append(line, Object.assign(document.createElement("p"), { className: "muted small", textContent: row.note }));
      }
      li.append(pill, body);
      if (row.action) {
        const button = Object.assign(document.createElement("button"), { className: "btn btn-small", type: "button", textContent: row.action.label });
        button.dataset.setupAction = row.action.id;
        li.append(button);
      }
      return li;
    }));
  }

  return { checklist, start, render };
});
