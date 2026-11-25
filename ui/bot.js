"use strict";
/* Nex: offline, rules-only assistant (no LLM, no network).
   Guarantees live in code, not in prose:
   - read-only: callLive() only ever forwards the three commands in ALLOWED_COMMANDS;
   - user text is capped, stripped of control chars and only ever shown via textContent;
   - event/file data is clipped and shown as data (<code>), never interpreted;
   - requests to change protection or delete files get a fixed refusal that points to the page;
   - at most 3 messages per second.
   Pure logic (Core) is separate from the DOM so scripts/test_bot.js can test it in Node. */
(function () {
  const ALLOWED_COMMANDS = Object.freeze(["get_dashboard_state", "get_events", "list_quarantine"]);
  const PAGES = Object.freeze(["overview", "engines", "activity", "quarantine", "canaries", "settings"]);
  const MAX_INPUT = 200;
  const RATE_MAX = 3;
  const RATE_WINDOW_MS = 1000;

  const TYPE_NOTES = {
    ZIP_BOMB: "An archive built to expand far beyond its size and exhaust the disk or memory. It was caught before anything was extracted.",
    LOTL_SCRIPT: "A built-in tool (PowerShell, cmd, mshta, osascript…) was started the way malware uses it, for example with a hidden window, an encoded command or a download.",
    KNOWN_MALWARE: "A file or program whose fingerprint (SHA-256) is on the known-malware list. This is a certain match, not a guess.",
    MALWARE_AI: "The on-device AI model scored this new program as malicious. The detail line lists what it noticed.",
    MALWARE_AI_PROCESS: "The on-device AI model scored the image of a running program as malicious.",
    RANSOMWARE_CANARY: "A decoy file that nothing should touch was changed: the typical first sign of ransomware encrypting files.",
    RANSOMWARE_SUSPECT: "A program changed many files in a way that looks like ransomware.",
    QUARANTINE_RESTORE: "You restored this file from quarantine to where it was found.",
    QUARANTINE_DELETE: "You deleted this file from quarantine for good.",
  };
  // Phrases -> threat types, most specific first.
  const TYPE_ALIASES = [
    [/known[ _-]?(bad|malware)/, ["KNOWN_MALWARE"]],
    [/malware[ _-]?ai[ _-]?process/, ["MALWARE_AI_PROCESS"]],
    [/malware[ _-]?ai/, ["MALWARE_AI"]],
    [/zip[ _-]?bomb/, ["ZIP_BOMB"]],
    [/lotl|living[ _-]off[ _-]the[ _-]land/, ["LOTL_SCRIPT"]],
    [/ransomware[ _-]?canary/, ["RANSOMWARE_CANARY"]],
    [/ransomware[ _-]?suspect/, ["RANSOMWARE_SUSPECT"]],
    [/quarantine[ _-]?restore/, ["QUARANTINE_RESTORE"]],
    [/quarantine[ _-]?delete/, ["QUARANTINE_DELETE"]],
    [/ransomware/, ["RANSOMWARE_CANARY", "RANSOMWARE_SUSPECT"]],
  ];
  const ENGINES = [
    ["known_bad_enabled", "Known threats check"],
    ["zip_bomb_enabled", "Compressed file check"],
    ["bin_ai_enabled", "New program check (AI)"],
    ["process_guard_enabled", "Sneaky command guard"],
    ["canary_enabled", "Ransomware tripwire"],
  ];

  const CONTROL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g;
  const clip = (value, max) => {
    const s = String(value === null || value === undefined ? "" : value).replace(CONTROL, " ").replace(/\s+/g, " ").trim();
    return s.length > max ? `${s.slice(0, max - 1)}…` : s;
  };
  const sanitizeInput = (value) => clip(value, 100000).slice(0, MAX_INPUT).trim();
  const fileName = (path) => clip(String(path || "").split(/[\\/]/).filter(Boolean).pop() || "unknown file", 48);
  const d = (text) => ({ d: text }); // a data segment, rendered in <code>
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  function relative(iso) {
    const ms = Date.now() - new Date(iso).getTime();
    if (!Number.isFinite(ms)) return "at an unknown time";
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return `${s} s ago`;
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${plural(Math.round(s / 86400), "day")} ago`;
  }

  function actionLabel(action) {
    const t = String(action || "");
    if (t.startsWith("DRY_RUN")) return "Dry run (nothing moved)";
    if (t.includes("QUARANTINE_FAILED") || t === "TERMINATE_FAILED") return "Failed";
    if (t.startsWith("TERMINATED") && t.includes("QUARANTINED")) return "Terminated and quarantined";
    if (t.startsWith("QUARANTINED")) return "Quarantined";
    if (t.startsWith("TERMINATED")) return "Terminated";
    if (t === "ALERT_RAISED") return "Alerted";
    return clip(t.split(/[\s=]/)[0].replace(/_/g, " ").toLowerCase(), 30) || "unknown";
  }

  /* Hard allowlist: the only door from the bot to the app. */
  function callLive(call, command, args) {
    if (!ALLOWED_COMMANDS.includes(command)) throw new Error(`Nex is read-only: command "${clip(command, 40)}" is not allowed.`);
    return call(command, args || {});
  }

  function makeLimiter(now) {
    const stamps = [];
    return function allow() {
      const t = now();
      while (stamps.length && t - stamps[0] >= RATE_WINDOW_MS) stamps.shift();
      if (stamps.length >= RATE_MAX) return false;
      stamps.push(t);
      return true;
    };
  }

  /* ---------- intent matching ---------- */
  const R = {
    secrets: /\b(token|session|cookie|password|secret|api[ _-]?key|local ?storage|credential)s?\b/,
    inject: /\b(ignore|forget|disregard|override)\b.*\b(previous|prior|above|earlier|your|all|these)\b.*\b(instruction|rule|prompt|guideline|polic)|system prompt|you are now|developer mode|jailbreak|pretend (to be|you)/,
    change: /\b(disable|deactivate|turn off|switch off|shut ?down|bypass|whitelist|exclude|uninstall|kill|enable|turn on|switch on|toggle|change|modify|update)\b.*\b(?:protection|engine|nex|guard|shield|canar|scan|ai\b|monitor|dry ?run|setting|threshold|everything|it\b)|^(please |can you |could you |would you |pls )*(stop|pause)\b/,
    destroy: /^(please |can you |could you |would you |pls |go ahead and |now )*(delete|remove|erase|wipe|purge|empty|restore|release|clear)\b/,
    nav: /^(please |can you |could you |pls )*(show|open|go to|goto|take me to|view|navigate to|bring up)\b/,
  };

  function findTypes(text) {
    const keys = Object.keys(TYPE_NOTES).filter((k) => text.toUpperCase().replace(/[\s-]+/g, "_").includes(k));
    if (keys.length) return keys.filter((k) => !keys.some((o) => o !== k && o.includes(k)));
    for (const [re, types] of TYPE_ALIASES) if (re.test(text)) return types;
    return [];
  }

  function classify(input) {
    const text = sanitizeInput(input).toLowerCase();
    if (!text) return { intent: "empty" };
    if (R.inject.test(text)) return { intent: "refuse", kind: "inject" };
    if (R.secrets.test(text)) return { intent: "refuse", kind: "secrets" };
    if (R.destroy.test(text)) return { intent: "refuse", kind: "delete" };
    if (R.change.test(text)) return { intent: "refuse", kind: /setting|threshold|dry ?run/.test(text) ? "settings" : "disable" };
    const wantsInfo = /\b(what|how many|how much|which|when|why)\b/.test(text);
    if (R.nav.test(text) && !wantsInfo) {
      if (/quarantine/.test(text)) return { intent: "nav", page: "quarantine" };
      if (/setting|preference|appearance/.test(text)) return { intent: "nav", page: "settings" };
      if (/activity|event|log|history|threat/.test(text)) return { intent: "nav", page: "activity" };
      if (/engine/.test(text)) return { intent: "nav", page: "engines" };
      if (/canar/.test(text)) return { intent: "nav", page: "canaries" };
      if (/overview|home|dashboard/.test(text)) return { intent: "nav", page: "overview" };
    }
    const types = findTypes(text);
    if (types.length && /\b(explain|what|mean|is|are|about|tell|describe|why)\b/.test(text)) return { intent: "explain", types };
    if (/\b(last|latest|recent|newest|previous)\b.*\b(threat|event|detection|alert|attack|catch|caught|block)/.test(text) || /what happened|any threats?\b|anything (bad|suspicious)/.test(text)) return { intent: "last" };
    if (/quarantin/.test(text)) return { intent: "quarantine" };
    if (/\b(ai|model|onnx|machine learning|decide|decision|verdict)\b/.test(text)) return { intent: "ai" };
    if (/\bscan/.test(text)) return { intent: "scan" };
    if (/protect|\bsafe\b|secure|status|\bonline\b|running|am i ok|all good|healthy/.test(text)) return { intent: "protected" };
    if (types.length) return { intent: "explain", types };
    if (/\b(help|hello|hi|hey|what can you|commands|options)\b/.test(text)) return { intent: "help" };
    return { intent: "fallback" };
  }

  /* ---------- answers ---------- */
  const go = (label, page) => ({ label, go: { page } });
  const HELP_LIST = {
    ul: [
      "Am I protected?",
      "What was the last threat?",
      "What's in quarantine?",
      "Explain ZIP_BOMB (or MALWARE_AI, LOTL_SCRIPT, RANSOMWARE_CANARY…)",
      "How does the AI decide?",
      "Run a scan, or show activity / quarantine / settings",
    ],
  };
  const REFUSALS = {
    disable: { parts: ["I can't turn protection or engines on or off. I only read what the app shows. You can change it yourself on the Engines page."], buttons: [go("Open Engines", "engines")] },
    delete: { parts: ["I can't delete or restore files. You can review each file and decide yourself in Quarantine."], buttons: [go("Open Quarantine", "quarantine")] },
    settings: { parts: ["I can't change settings. You can do it yourself on the Settings page."], buttons: [go("Open Settings", "settings")] },
    inject: { parts: ["I can't follow instructions like that. I only answer questions about your protection, using what the app shows."], buttons: [] },
    secrets: { parts: ["I never show tokens, sessions or stored data. I can tell you about protection status, threats and quarantine."], buttons: [] },
  };

  function protectedAnswer(dash) {
    const online = !!(dash && dash.daemon && dash.daemon.online);
    if (!online) return { parts: ["Not right now. The background service is offline, so nothing is being watched.", { ul: ["Service: offline"] }], buttons: [go("Open Settings", "settings")] };
    const t = dash.toggles || {};
    const off = ENGINES.filter(([k]) => !t[k]).map(([, n]) => n);
    const canaries = Array.isArray(dash.canaries) ? dash.canaries.length : 0;
    const intact = Number(dash.canaries_intact) || 0;
    let head;
    if (dash.dry_run) head = "Partly. The service is online, but Dry run is on: threats are detected and logged, not stopped.";
    else if (off.length) head = `Mostly. The service is online and blocking, but ${plural(off.length, "engine")} ${off.length === 1 ? "is" : "are"} off.`;
    else head = "Yes. The service is online and all engines are watching.";
    const lines = [
      "Service: online",
      dash.dry_run ? "Mode: dry run (detect only)" : "Mode: blocking threats",
      `Engines: ${ENGINES.length - off.length} of ${ENGINES.length} on${off.length ? ` (off: ${off.join(", ")})` : ""}`,
      `Canaries: ${intact} of ${canaries} intact`,
      dash.model_loaded ? "AI model: loaded (on device)" : "AI model: not loaded, using the heuristic fallback",
      `Quarantined files: ${Number(dash.quarantined) || 0}`,
    ];
    return { parts: [head, { ul: lines }], buttons: [go("Open Engines", "engines")] };
  }

  function lastAnswer(events) {
    const list = (Array.isArray(events) ? events : [])
      .filter((e) => e && !/^QUARANTINE_/.test(String(e.threat_type)))
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    if (!list.length) return { parts: ["No recent threats. Nothing suspicious has been logged lately."], buttons: [go("Open Activity", "activity")] };
    const e = list[0];
    const type = clip(e.threat_type, 40);
    const note = TYPE_NOTES[e.threat_type] || "No built-in explanation for this type yet.";
    const parts = [
      ["The most recent threat was ", d(type), ` ${relative(e.timestamp)}.`],
      { ul: [["File: ", d(fileName(e.target))], `Action: ${actionLabel(e.action_taken)}`, `Severity: ${clip(e.severity, 20) || "unknown"}`] },
    ];
    if (e.details) parts.push(["Detail (from the event log, shown as data): ", d(clip(e.details, 120))]);
    parts.push(note);
    return { parts, buttons: [{ label: "Open this event", go: { activity: { open: String(e.id) } } }, go("All activity", "activity")] };
  }

  function quarantineAnswer(items) {
    const list = Array.isArray(items) ? items : [];
    if (!list.length) return { parts: ["Quarantine is empty. No files are being held."], buttons: [go("Open Quarantine", "quarantine")] };
    const newest = list.reduce((b, q) => (!b || String(q.quarantined_at) > String(b.quarantined_at) ? q : b), null);
    return {
      parts: [
        `${plural(list.length, "file")} ${list.length === 1 ? "is" : "are"} held in quarantine.`,
        ["Newest: ", d(fileName(newest.original_path)), ` (${clip(newest.threat_type, 40)}), ${relative(newest.quarantined_at)}.`],
        "Files there are inert. Only you can restore or delete them, from the Quarantine page.",
      ],
      buttons: [go("Open Quarantine", "quarantine")],
    };
  }

  const explainAnswer = (types) => ({
    parts: types.map((t) => [d(t), `: ${TYPE_NOTES[t]}`]),
    buttons: types.slice(0, 2).map((t) => ({ label: `See ${t}`, go: { activity: { type: t } } })),
  });

  function aiAnswer(dash) {
    const live = dash && typeof dash.model_loaded === "boolean" ? (dash.model_loaded ? "The model is loaded right now." : "The model is not loaded, so a simple heuristic is used instead.") : null;
    const parts = [
      "A small ONNX model runs on this device. Nothing is sent over the network.",
      "It looks at features of a new file or running program and scores how malware-like it is. When it flags something, the event carries an explanation string listing what it noticed.",
      "It never deletes anything. A flagged file is moved to quarantine, and only you can restore or delete it.",
    ];
    if (live) parts.push(live);
    return { parts, buttons: [go("Open Engines", "engines")] };
  }

  const SCAN = { parts: ["I can't run a scan myself. Quick Scan is a button at the top right of the Overview page. I'll take you there and you press it."], buttons: [go("Go to Overview", "overview")] };
  const NAV_LABEL = { quarantine: "Quarantine", settings: "Settings", activity: "Activity", engines: "Engines", canaries: "Canaries", overview: "Overview" };
  const FALLBACK = { parts: ["I'm not sure what you mean. I can answer:", HELP_LIST], buttons: [] };
  const HELP = { parts: ["Hi, I'm Nex. I'm offline and read-only: I answer from what the app shows right now. Try:", HELP_LIST], buttons: [] };

  async function answer(intentInfo, call) {
    const live = (cmd, args) => callLive(call, cmd, args);
    try {
      switch (intentInfo.intent) {
        case "refuse": return REFUSALS[intentInfo.kind];
        case "empty": return { parts: ["Type a question, or pick one below."], buttons: [] };
        case "nav": return { parts: [`Opening ${NAV_LABEL[intentInfo.page]}.`], buttons: [go(`Open ${NAV_LABEL[intentInfo.page]}`, intentInfo.page)], autoGo: { page: intentInfo.page } };
        case "scan": return SCAN;
        case "help": return HELP;
        case "explain": return explainAnswer(intentInfo.types);
        case "protected": return protectedAnswer(await live("get_dashboard_state"));
        case "last": return lastAnswer(await live("get_events", { limit: 5, query: null, severity: "ALL" }));
        case "quarantine": return quarantineAnswer(await live("list_quarantine"));
        case "ai": return aiAnswer(await live("get_dashboard_state").catch(() => null));
        default: return FALLBACK;
      }
    } catch (error) {
      return { parts: ["I couldn't read live data right now. Open The Nex from its desktop app and make sure the service is running.", ["Reason: ", d(clip(error && error.message ? error.message : error, 100))]], buttons: [] };
    }
  }

  /* The conversational core: raw user text in, reply object out. No DOM. */
  function createBrain(deps) {
    const allow = makeLimiter(deps.now || Date.now);
    const runGo = (target) => {
      if (target && target.activity && typeof deps.openActivity === "function") return deps.openActivity(target.activity);
      if (target && PAGES.includes(target.page) && typeof deps.showPage === "function") return deps.showPage(target.page);
    };
    return {
      run: runGo,
      async ask(raw) {
        const text = sanitizeInput(raw);
        if (!allow()) return { limited: true, text, parts: ["One moment, I can only take 3 messages per second."], buttons: [] };
        const reply = await answer(classify(text), deps.call);
        if (reply.autoGo) runGo(reply.autoGo);
        return { text, ...reply };
      },
    };
  }

  const Core = { ALLOWED_COMMANDS, MAX_INPUT, TYPE_NOTES, sanitizeInput, clip, classify, callLive, makeLimiter, answer, createBrain };

  /* ---------- DOM ---------- */
  const SVG_NS = "http://www.w3.org/2000/svg";
  function svgEl(doc, tag, attrs, children) {
    const n = doc.createElementNS(SVG_NS, tag);
    for (const k of Object.keys(attrs || {})) n.setAttribute(k, attrs[k]);
    for (const c of children || []) n.appendChild(c);
    return n;
  }
  /* Gyroscope bot: ring + two crossing gimbals + hub, no poles. Spin is CSS (bot.css). */
  function avatar(doc) {
    const gimbal = (cls, tilt) => svgEl(doc, "g", { transform: `rotate(${tilt} 16 16)` }, [svgEl(doc, "g", { class: `nb-spin ${cls}` }, [svgEl(doc, "ellipse", { cx: 16, cy: 16, rx: 11.5, ry: 4.6, class: "nb-gimbal" })])]);
    return svgEl(doc, "svg", { viewBox: "0 0 32 32", class: "nb-avatar", "aria-hidden": "true", focusable: "false" }, [
      svgEl(doc, "circle", { cx: 16, cy: 16, r: 13, class: "nb-ring" }),
      gimbal("a", 35), gimbal("b", -35),
      svgEl(doc, "circle", { cx: 16, cy: 16, r: 3, class: "nb-hub" }),
    ]);
  }

  function lineNodes(doc, line) {
    return (Array.isArray(line) ? line : [line]).map((seg) => {
      if (seg && typeof seg === "object") { const c = doc.createElement("code"); c.textContent = seg.d; return c; }
      return doc.createTextNode(String(seg));
    });
  }

  /* Everything user- or data-derived goes through textContent / text nodes. */
  function renderBody(doc, reply, onGo) {
    const box = doc.createElement("div");
    for (const part of reply.parts) {
      if (part && part.ul) {
        const ul = doc.createElement("ul");
        for (const item of part.ul) { const li = doc.createElement("li"); for (const n of lineNodes(doc, item)) li.appendChild(n); ul.appendChild(li); }
        box.appendChild(ul);
      } else {
        const p = doc.createElement("p");
        for (const n of lineNodes(doc, part)) p.appendChild(n);
        box.appendChild(p);
      }
    }
    if (reply.buttons && reply.buttons.length) {
      const row = doc.createElement("div");
      row.className = "nb-actions";
      for (const b of reply.buttons) {
        const btn = doc.createElement("button");
        btn.type = "button";
        btn.className = "nb-action";
        btn.textContent = b.label;
        btn.addEventListener("click", () => onGo(b.go));
        row.appendChild(btn);
      }
      box.appendChild(row);
    }
    return box;
  }
  Core.renderBody = renderBody;

  const CHIPS = ["Am I protected?", "What was the last threat?", "What's in quarantine?", "How does the AI decide?", "Run a scan"];

  function start(deps) {
    const doc = document;
    const host = doc.getElementById("nexbot");
    if (!host || host.dataset.ready) return;
    host.dataset.ready = "1";
    const brain = createBrain(deps);
    const el = (tag, cls, text) => { const n = doc.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };

    const launcher = el("button", "nb-launcher");
    launcher.type = "button";
    launcher.setAttribute("aria-label", "Ask Nex, the offline assistant");
    launcher.setAttribute("aria-expanded", "false");
    launcher.setAttribute("aria-controls", "nb-panel");
    launcher.appendChild(avatar(doc));

    const panel = el("section", "nb-panel");
    panel.id = "nb-panel";
    panel.hidden = true;
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Nex assistant");
    const head = el("header", "nb-head");
    const tile = el("span", "nb-tile"); tile.appendChild(avatar(doc));
    const title = el("div", "nb-title"); title.append(el("b", "", "Nex"), el("span", "", "Offline assistant · read-only"));
    const close = el("button", "nb-close", "×");
    close.type = "button"; close.setAttribute("aria-label", "Close Nex");
    head.append(tile, title, close);

    const msgs = el("div", "nb-msgs");
    msgs.setAttribute("aria-live", "polite");
    msgs.setAttribute("aria-relevant", "additions");
    msgs.tabIndex = 0;
    msgs.setAttribute("aria-label", "Conversation with Nex");
    const chips = el("div", "nb-chips");
    const form = el("form", "nb-form");
    form.autocomplete = "off";
    const input = el("input", "nb-input");
    input.type = "text"; input.maxLength = MAX_INPUT; input.placeholder = "Ask about your protection…";
    input.setAttribute("aria-label", "Message to Nex");
    const send = el("button", "nb-send", "Send");
    send.type = "submit";
    form.append(input, send);
    panel.append(head, msgs, chips, form);
    host.append(panel, launcher);
    host.hidden = false;

    const onGo = (target) => { try { brain.run(target); } catch (e) { /* navigation must never break the panel */ } };
    const addBot = (reply, extra) => {
      const m = el("div", `nb-msg bot${extra ? ` ${extra}` : ""}`);
      m.appendChild(renderBody(doc, reply, onGo));
      msgs.appendChild(m);
      msgs.scrollTop = msgs.scrollHeight;
    };
    const addUser = (text) => { msgs.appendChild(el("div", "nb-msg user", text)); msgs.scrollTop = msgs.scrollHeight; };

    let queue = Promise.resolve();
    const submit = (raw) => {
      const text = sanitizeInput(raw);
      if (!text) return;
      queue = queue.then(async () => {
        const reply = await brain.ask(text);
        if (reply.limited) return addBot(reply, "note");
        addUser(reply.text);
        addBot(reply);
      }).catch(() => {});
    };
    for (const label of CHIPS) {
      const c = el("button", "nb-chip", label);
      c.type = "button";
      c.addEventListener("click", () => { submit(label); input.focus(); });
      chips.appendChild(c);
    }
    form.addEventListener("submit", (e) => { e.preventDefault(); submit(input.value); input.value = ""; });

    let greeted = false;
    const setOpen = (open) => {
      panel.hidden = !open;
      launcher.setAttribute("aria-expanded", String(open));
      if (open) {
        if (!greeted) { greeted = true; addBot(HELP); }
        input.focus();
      } else launcher.focus();
    };
    launcher.addEventListener("click", () => setOpen(panel.hidden));
    close.addEventListener("click", () => setOpen(false));
    doc.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) { e.preventDefault(); setOpen(false); } });
  }

  window.NexBot = { start, _core: Core };
})();
