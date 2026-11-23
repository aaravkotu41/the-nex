"use strict";

const tauri = window.__TAURI__;
const invoke = tauri && tauri.core && typeof tauri.core.invoke === "function" ? tauri.core.invoke : null;

const REFRESH_MS = 2000;
const CONFIRM_MS = 4000;
const OVERVIEW_EVENTS = 8;
const PAGE_TITLES = {
  overview: "Overview",
  engines: "Engines",
  activity: "Activity",
  quarantine: "Quarantine",
  canaries: "Canaries",
  settings: "Settings",
  aegismesh: "AegisMesh",
};
const PAGE_SUBS = {
  engines: "Four local engines. Nothing leaves this computer.",
  activity: "Everything the engines saw and did, newest first.",
  quarantine: "Files that were stopped. Restore or delete them here.",
  canaries: "Decoy files that reveal ransomware the moment they change.",
  settings: "Background service, watched folders and the look of the app.",
  aegismesh: "Silent SOS simulation: wearables, tap rhythms, emergency signs and the relay mesh.",
};

function greeting() {
  const now = new Date();
  const hour = now.getHours();
  const part = hour < 5 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  return `${part} · ${now.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })}`;
}
const TOGGLE_FIELDS = {
  zip_bomb: "zip_bomb_enabled",
  bin_ai: "bin_ai_enabled",
  process_guard: "process_guard_enabled",
  canary: "canary_enabled",
  dry_run: "dry_run",
};
const RED_TYPES = new Set(["ZIP_BOMB", "RANSOMWARE_CANARY", "RANSOMWARE_SUSPECT", "MALWARE_AI", "MALWARE_AI_PROCESS"]);
const AMBER_TYPES = new Set(["LOTL_SCRIPT"]);
const GREEN_TYPES = new Set(["QUARANTINE_RESTORE"]);

const state = {
  page: "overview",
  query: "",
  severity: "ALL",
  dashboard: null,
  quarantine: [],
  refreshing: false,
  pendingToggles: new Set(),
  confirm: null,
  openEvent: null,
  openQuarantine: null,
  activityType: null, // Activity filters set by clicking the overview (a threat type, a day)
  activityDay: null,
  scanning: false,
};

const SEARCH_PAGES = new Set(["overview", "activity", "quarantine", "canaries"]);
const TYPE_NOTES = {
  ZIP_BOMB: "An archive built to expand far beyond its size and exhaust the disk or memory. It was caught before anything was extracted.",
  LOTL_SCRIPT: "A built-in tool (PowerShell, cmd, mshta, osascript…) was started the way malware uses it, for example with a hidden window, an encoded command or a download.",
  MALWARE_AI: "The on-device AI model scored this new program as malicious. The detail line lists what it noticed.",
  MALWARE_AI_PROCESS: "The on-device AI model scored the image of a running program as malicious.",
  RANSOMWARE_CANARY: "A decoy file that nothing should touch was changed: the typical first sign of ransomware encrypting files.",
  RANSOMWARE_SUSPECT: "A program changed many files in a way that looks like ransomware.",
  QUARANTINE_RESTORE: "You restored this file from quarantine to where it was found.",
  QUARANTINE_DELETE: "You deleted this file from quarantine for good.",
};

const $ = (id) => document.getElementById(id);

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.title) node.title = options.title;
  for (const [key, value] of Object.entries(options.attrs || {})) node.setAttribute(key, value);
  for (const child of children) node.append(child);
  return node;
}

function call(command, args) {
  if (!invoke) return Promise.reject(new Error("The Nex desktop runtime is not available in this window."));
  return invoke(command, args || {});
}

function errorText(error) {
  if (typeof error === "string") return error;
  return (error && error.message) || String(error);
}

let noticeTimer = null;
function notice(message, isError) {
  const box = $("notice");
  box.textContent = message;
  box.classList.toggle("error", Boolean(isError));
  box.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { box.hidden = true; }, isError ? 9000 : 5000);
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString([], { hour12: false });
}

function formatDateTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { hour12: false });
}

/** Counts a tile's number up (or down) to its new value instead of jumping. */
function setCount(node, value) {
  const target = Number(value) || 0;
  const from = Number(node.dataset.value);
  node.dataset.value = String(target);
  if (!Number.isFinite(from) || from === target || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    node.textContent = count(target);
    return;
  }
  const start = performance.now();
  const step = (now) => {
    if (node.dataset.value !== String(target)) return; // a newer value took over
    const k = Math.min(1, (now - start) / 700);
    const eased = 1 - Math.pow(1 - k, 3);
    node.textContent = count(Math.round(from + (target - from) * eased));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** "20:06:24" today, "Yesterday 19:07" or "Nov 21, 19:07" before that. */
function formatWhen(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  const now = new Date();
  if (sameDay(date, now)) return date.toLocaleTimeString([], { hour12: false });
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (sameDay(date, yesterday)) return `Yesterday ${time}`;
  return `${date.toLocaleDateString([], { month: "short", day: "numeric" })}, ${time}`;
}

/** "40 s ago", "5 min ago", "3 h ago", "2 days ago". */
function relativeTime(iso) {
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "";
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  const days = Math.round(s / 86400);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function folderOf(path) {
  const text = String(path || "");
  const cut = Math.max(text.lastIndexOf("\\"), text.lastIndexOf("/"));
  return cut > 0 ? text.slice(0, cut) : "";
}

function severityKey(value) {
  return String(value || "").toUpperCase();
}

function copyButton(text, label = "Copy") {
  const button = el("button", { className: "btn btn-small", text: label, attrs: { type: "button" } });
  button.addEventListener("click", async (event) => {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => { button.textContent = label; }, 1400);
  });
  return button;
}

function detailGrid(entries, note) {
  const grid = el("dl", { className: "detail-grid" });
  for (const [term, value, copy] of entries) {
    const dd = el("dd", {}, [el("span", { text: value })]);
    if (copy) dd.append(copyButton(copy));
    grid.append(el("dt", { text: term }), dd);
  }
  if (note) grid.append(el("p", { className: "detail-note", text: note }));
  return grid;
}

/** A clickable row plus its hidden detail row; `open` shows the details. */
function expandable(cells, detail, open, onToggle, columns) {
  const row = el("tr", { className: `expand-row${open ? " open" : ""}`, attrs: { tabindex: "0", "aria-expanded": String(open) } }, cells);
  row.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    onToggle();
  });
  row.addEventListener("keydown", (event) => {
    if ((event.key === "Enter" || event.key === " ") && event.target === row) {
      event.preventDefault();
      onToggle();
    }
  });
  if (!open) return [row];
  const cell = el("td", { attrs: { colspan: String(columns) } }, [detail]);
  return [row, el("tr", { className: "detail-row" }, [cell])];
}

const chevron = () => el("span", { className: "chev", attrs: { "aria-hidden": "true" } });

function formatShortDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function formatUptime(seconds) {
  if (seconds == null) return "";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function count(value) {
  return Number(value || 0).toLocaleString();
}

function shortPath(path) {
  const text = String(path || "");
  const separator = text.includes("\\") ? "\\" : "/";
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? text : parts.slice(-2).join(separator);
}

function fileName(path) {
  const parts = String(path || "").split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path || "");
}

function typeClass(type) {
  if (RED_TYPES.has(type)) return "pill red";
  if (AMBER_TYPES.has(type)) return "pill amber";
  if (GREEN_TYPES.has(type)) return "pill green";
  return "pill";
}

function actionLabel(action) {
  const text = String(action || "");
  if (text.startsWith("DRY_RUN")) return "Dry run";
  if (text.includes("QUARANTINE_FAILED") || text === "TERMINATE_FAILED") return "Failed";
  if (text.startsWith("TERMINATED") && text.includes("QUARANTINED")) return "Terminated + quarantined";
  if (text.startsWith("QUARANTINED")) return "Quarantined";
  if (text.startsWith("TERMINATED")) return "Terminated";
  if (text === "ALERT_RAISED") return "Alerted";
  if (text === "RESTORED") return "Restored";
  if (text === "DELETED") return "Deleted";
  const word = text.split(/[\s=]/)[0].replace(/_/g, " ");
  return word ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() : "—";
}

function severityBadge(severity) {
  const key = severityKey(severity);
  return el("span", { className: `sev ${key.toLowerCase()}`, text: key.charAt(0) + key.slice(1).toLowerCase() });
}

function eventRow(event) {
  const row = el("tr", { title: "Open in Activity", attrs: { tabindex: "0" } }, [
    el("td", { text: formatWhen(event.timestamp), title: formatDateTime(event.timestamp) }),
    el("td", {}, [el("span", { className: typeClass(event.threat_type), text: event.threat_type })]),
    el("td", { text: shortPath(event.target), title: event.target }),
    el("td", { text: event.details, title: event.details }),
    el("td", { text: actionLabel(event.action_taken), title: event.action_taken }),
  ]);
  const open = () => openActivity({ open: event.id });
  row.addEventListener("click", open);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
  return row;
}

const DAY_MS = 86400000;

/** Opens Activity, optionally filtered to one threat type or one day, or with one event open. */
function openActivity({ type = null, day = null, open = null } = {}) {
  state.activityType = type;
  state.activityDay = day;
  state.openEvent = open;
  state.severity = "ALL";
  for (const pill of document.querySelectorAll(".pill-filter")) pill.classList.toggle("active", pill.dataset.severity === "ALL");
  showPage("activity");
}

function renderActivityFilters() {
  const chips = [];
  if (state.activityType) chips.push(["Type", state.activityType, () => { state.activityType = null; }]);
  if (state.activityDay !== null) {
    const label = new Date(state.activityDay).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short" });
    chips.push(["Day", label, () => { state.activityDay = null; }]);
  }
  const holder = $("activity-filters");
  holder.hidden = chips.length === 0;
  replaceIfChanged(holder, JSON.stringify(chips.map((c) => c.slice(0, 2))), () => chips.map(([name, value, clear]) => {
    const close = el("button", { text: "×", title: `Show every ${name.toLowerCase()}`, attrs: { type: "button", "aria-label": `Clear the ${name.toLowerCase()} filter` } });
    close.addEventListener("click", () => { clear(); refresh(true); });
    return el("span", { className: "filter-chip" }, [el("small", { text: name }), el("span", { text: value }), close]);
  }));
}

function activityRows(event) {
  const open = state.openEvent === event.id;
  const cells = [
    el("td", {}, [
      el("span", { className: "cell-main", text: formatWhen(event.timestamp) }),
      el("span", { className: "cell-sub", text: relativeTime(event.timestamp) }),
    ]),
    el("td", {}, [el("span", { className: typeClass(event.threat_type), text: event.threat_type })]),
    el("td", { className: "sans" }, [severityBadge(event.severity)]),
    el("td", { title: event.target }, [
      el("span", { className: "cell-main", text: fileName(event.target) }),
      el("span", { className: "cell-sub", text: folderOf(event.target) || "—" }),
    ]),
    el("td", { text: event.details, title: event.details }),
    el("td", { className: "sans", text: actionLabel(event.action_taken), title: event.action_taken }),
    el("td", {}, [chevron()]),
  ];
  const detail = detailGrid([
    ["When", `${formatDateTime(event.timestamp)} (${relativeTime(event.timestamp)})`],
    ["Target", event.target, event.target],
    ["Detail", event.details],
    ["Action taken", event.action_taken],
    ["Event ID", event.id, event.id],
  ], TYPE_NOTES[event.threat_type]);
  return expandable(cells, detail, open, () => {
    state.openEvent = open ? null : event.id;
    loadEvents().catch(() => {});
  }, 7);
}

function setSwitch(button, checked) {
  button.setAttribute("aria-checked", checked ? "true" : "false");
}

function renderToggles(toggles, enabled) {
  for (const button of document.querySelectorAll(".switch[data-engine]")) {
    const engine = button.dataset.engine;
    if (state.pendingToggles.has(engine)) continue;
    setSwitch(button, Boolean(toggles && toggles[TOGGLE_FIELDS[engine]]));
    button.disabled = !enabled;
  }
}

function focusEngine(engine) {
  const row = document.querySelector(`[data-engine-row="${engine}"]`);
  if (!row) return;
  requestAnimationFrame(() => {
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    row.classList.remove("flash");
    void row.offsetWidth; // restart the highlight
    row.classList.add("flash");
  });
}

function buildEngineRows() {
  const rows = $("engine-rows");
  const engines = [
    ["zip_bomb", "Zip Bomb Guard", "Central-directory inspection before extraction: ratio, size, overlap and nesting."],
    ["bin_ai", "ONNX Binary AI", "Scores new PE and Mach-O files and processes with the local tract model."],
    ["process_guard", "LotL Process Guard", "Terminates script hosts and shells launched with download or obfuscation patterns."],
    ["canary", "Canary Honeypots", "Decoy documents that reveal ransomware the moment they change."],
  ];
  for (const [engine, title, description] of engines) {
    const thresholds = el("div", { className: "thresholds", attrs: { "data-thresholds": engine } });
    rows.append(el("div", { className: "row", attrs: { "data-engine-row": engine } }, [
      el("div", {}, [el("h3", { text: title }), el("p", { className: "muted", text: description }), thresholds]),
      el("button", { className: "switch", attrs: { role: "switch", "aria-checked": "false", "data-engine": engine, "aria-label": title } }),
    ]));
  }
}

function fillThresholds(engine, values) {
  const holder = document.querySelector(`[data-thresholds="${engine}"]`);
  if (!holder) return;
  holder.replaceChildren(...values.map((value) => el("span", { className: "pill", text: value })));
}

function facts(list, entries, badges) {
  list.replaceChildren(...entries.flatMap(([term, value]) => [
    el("dt", { text: term }),
    badges ? el("dd", {}, [el("code", { className: "path-badge", text: value })]) : el("dd", { text: value }),
  ]));
}

function renderDashboard(d) {
  const online = d.daemon.online;
  const footerDot = $("service-dot");
  footerDot.className = online ? "dot ok" : "dot";
  $("service-text").textContent = online
    ? `Service Active · ${(d.daemon.memory_mb || 0).toFixed(1)} MB`
    : "Daemon Offline";

  const topDot = $("top-status-dot");
  const topText = $("top-status-text");
  if (!online) {
    topDot.className = "dot bad";
    topText.textContent = "Service offline";
  } else if (d.dry_run) {
    topDot.className = "dot warn";
    topText.textContent = "Dry run · detect only";
  } else {
    topDot.className = "dot ok";
    topText.textContent = `Protected · ${protectionScore(d).score}`;
  }

  const protection = $("protection-dot");
  if (!online) {
    protection.className = "dot bad";
    $("protection-text").textContent = "Unprotected — Service Offline";
  } else if (d.dry_run) {
    protection.className = "dot warn";
    $("protection-text").textContent = "Dry Run — Detect Only";
  } else {
    protection.className = "dot ok";
    $("protection-text").textContent = "Protected — Local Rust Engine";
  }
  setCount($("stat-scanned"), d.scanned);
  setCount($("stat-threats"), d.threats_detected);
  setCount($("stat-quarantined"), d.quarantined);
  $("stat-cpu").textContent = online ? `${(d.daemon.cpu_percent || 0).toFixed(1)}%` : "—";
  renderScore(d);

  const badge = $("quarantine-badge");
  badge.textContent = String(d.quarantined);
  badge.hidden = d.quarantined === 0;

  const t = d.thresholds;
  $("card-zip").textContent = `Ratio >${t.max_ratio}:1 · Depth ≤${t.max_depth} · Pre-extraction`;
  let model;
  if (d.model_loaded) model = "thenex_model.onnx · Offline · Local tract";
  else if (d.model_present) model = "thenex_model.onnx · Loads with the service";
  else model = "Model missing · Heuristic fallback";
  $("card-ai").textContent = model;
  $("card-lotl").textContent = `${count(d.processes_watched)} processes watched · Shell & Script Shield`;
  $("card-canary").textContent = `${d.canaries_intact} decoy file${d.canaries_intact === 1 ? "" : "s"} intact · Desktop & Docs`;
  renderToggles(d.toggles, true);

  fillThresholds("zip_bomb", [
    `ratio > ${t.max_ratio}:1 above ${t.min_ratio_check_mb} MB`,
    `size ≤ ${t.max_uncompressed_gb} GB`,
    `depth ≤ ${t.max_depth}`,
    `nested read ≤ ${t.nested_read_mb} MB`,
  ]);
  fillThresholds("bin_ai", [`malicious ≥ ${t.ai_threshold}`, d.model_loaded ? "onnx" : "heuristic"]);
  fillThresholds("process_guard", [`${count(d.processes_watched)} watched`, `${count(d.processes_inspected)} inspected`]);
  fillThresholds("canary", [`${d.canaries_intact}/${d.canaries.length} intact`, "2s self-write cooldown"]);

  facts($("model-facts"), [
    ["Model file", d.model_path],
    ["Present", d.model_present ? "yes" : "no"],
    ["Service engine", online ? (d.model_loaded ? "ONNX (tract)" : "heuristic fallback") : "service offline"],
    ["Decision threshold", String(t.ai_threshold)],
  ]);

  renderCanaries(d.canaries);

  const servicePill = $("service-state");
  if (d.service_installed && online) {
    servicePill.className = "pill status green";
    servicePill.textContent = "Installed · running";
  } else if (d.service_installed) {
    servicePill.className = "pill status amber";
    servicePill.textContent = "Installed · stopped";
  } else {
    servicePill.className = "pill status";
    servicePill.textContent = "Not installed";
  }
  $("service-detail").textContent = online
    ? `PID ${d.daemon.pid} · v${d.daemon.version} · up ${formatUptime(d.daemon.uptime_seconds)} · ${(d.daemon.memory_mb || 0).toFixed(1)} MB`
    : "The engine is not running in the background.";
  $("install-service").textContent = d.service_installed ? "Reinstall" : "Install";
  $("uninstall-service").disabled = !d.service_installed;

  replaceIfChanged($("watched-dirs"), JSON.stringify(d.watched_dirs), () => (d.watched_dirs.length
    ? d.watched_dirs.map((dir) => el("li", {}, [el("code", { className: "path-badge", text: dir })]))
    : [el("li", { className: "muted", text: "No watched folders found." })]));
  facts($("data-facts"), [
    ["Data folder", d.data_dir],
    ["Event log", d.events_log],
    ["Settings", d.settings_file],
    ["Platform", d.platform],
  ], true);
}

/** 0-100: service 30, engines 40, AI model 10, canaries 10, blocking (not dry run) 10. */
function protectionScore(d) {
  const t = d.toggles || {};
  const enginesOn = ["zip_bomb_enabled", "bin_ai_enabled", "process_guard_enabled", "canary_enabled"].filter((k) => t[k]).length;
  const canaries = (d.canaries || []).length;
  const canariesOk = canaries > 0 && d.canaries_intact === canaries;
  const items = [
    { ok: d.daemon.online, text: d.daemon.online ? "Background service running" : "Background service offline", goto: "settings" },
    { ok: enginesOn === 4, text: `${enginesOn} of 4 engines on`, goto: "engines" },
    { ok: Boolean(d.model_loaded), text: d.model_loaded ? "AI model loaded" : "AI on heuristic fallback", goto: "engines", focus: "bin_ai" },
    { ok: canariesOk, text: `${d.canaries_intact} of ${canaries} canaries intact`, goto: "canaries" },
    { ok: !d.dry_run, text: d.dry_run ? "Dry run: detecting only" : "Blocking threats", goto: "engines" },
  ];
  const score = d.daemon.online
    ? Math.round(30 + (40 * enginesOn) / 4 + (d.model_loaded ? 10 : 0) + (canariesOk ? 10 : 0) + (d.dry_run ? 0 : 10))
    : 0;
  return { score, items };
}

function setRing(score, tone) {
  $("ring-value").style.strokeDasharray = `${score} 100`;
  $("score-value").textContent = score === null ? "–" : String(score);
  $("hero").dataset.tone = tone;
}

function renderScore(d) {
  const { score, items } = protectionScore(d);
  const allOk = items.every((item) => item.ok);
  const tone = allOk ? "ok" : score >= 60 ? "warn" : "bad";
  setRing(score, tone);
  $("protection-detail").textContent = allOk
    ? "Every engine is active. New downloads, archives and processes are checked as they appear."
    : "Some protection is off or degraded; the items marked ! need attention.";
  replaceIfChanged($("score-items"), JSON.stringify(items), () => items.map((item) => el("li", { className: item.ok ? "ok" : "no" }, [
    el("button", { text: item.text, attrs: { type: "button", "data-goto": item.goto, ...(item.focus ? { "data-focus": item.focus } : {}) } }),
  ])));
}

const CHART_REFRESH_MS = 30000;

async function loadChart(force) {
  if (!force && state.chartAt && Date.now() - state.chartAt < CHART_REFRESH_MS) return;
  state.chartAt = Date.now();
  const events = await call("get_events", { limit: 1000, query: null, severity: "ALL" }).catch(() => []);
  const days = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = 6; i >= 0; i--) {
    const day = new Date(today);
    day.setDate(day.getDate() - i);
    days.push({ start: day.getTime(), label: day.toLocaleDateString(undefined, { weekday: "short" }), critical: 0, high: 0, other: 0 });
  }
  for (const event of events) {
    const severity = String(event.severity || "").toLowerCase();
    if (severity === "low") continue; // restores, deletions and scan summaries are not threats
    const t = Date.parse(event.timestamp);
    for (let i = days.length - 1; i >= 0; i--) {
      if (t >= days[i].start) {
        if (i === days.length - 1 || t < days[i + 1].start) days[i][severity === "critical" ? "critical" : severity === "high" ? "high" : "other"]++;
        break;
      }
    }
  }
  const byType = new Map();
  for (const event of events) {
    if (String(event.severity || "").toLowerCase() === "low") continue;
    if (Date.parse(event.timestamp) < days[0].start) continue;
    byType.set(event.threat_type, (byType.get(event.threat_type) || 0) + 1);
  }
  renderChartFacts(days, byType);
  const max = Math.max(1, ...days.map((d) => d.critical + d.high + d.other));
  replaceIfChanged($("threat-chart"), JSON.stringify(days), () => days.map((d, index) => {
    const total = d.critical + d.high + d.other;
    const fill = el("div", { className: "bar-fill" });
    fill.style.setProperty("--i", String(index));
    for (const kind of ["critical", "high", "other"]) {
      if (!d[kind]) continue;
      const seg = el("div", { className: `seg ${kind}` });
      seg.style.height = `${(d[kind] / max) * 100}%`;
      fill.append(seg);
    }
    const stack = el("div", { className: "bar-stack" }, [fill]);
    const col = el("button", {
      className: `bar-col${index === days.length - 1 ? " today" : ""}`,
      title: `${d.label}: ${total} threat${total === 1 ? "" : "s"}. Click to see them.`,
      attrs: { type: "button" },
    }, [
      el("b", { className: total ? "mono" : "mono zero", text: String(total) }),
      stack,
      el("span", { text: d.label }),
    ]);
    col.addEventListener("click", () => openActivity({ day: d.start }));
    return col;
  }));
}

const TYPE_COLOURS = {
  ZIP_BOMB: "linear-gradient(90deg, #FF5FA2, #FF5C7A)",
  RANSOMWARE_CANARY: "linear-gradient(90deg, #FF5FA2, #FF5C7A)",
  RANSOMWARE_SUSPECT: "linear-gradient(90deg, #FF5FA2, #FF5C7A)",
  MALWARE_AI: "linear-gradient(90deg, #9B6BFF, #6E7BFF)",
  MALWARE_AI_PROCESS: "linear-gradient(90deg, #9B6BFF, #6E7BFF)",
  LOTL_SCRIPT: "linear-gradient(90deg, #FFD27A, #FFB547)",
};

function renderChartFacts(days, byType) {
  const totals = days.map((d) => d.critical + d.high + d.other);
  const week = totals.reduce((a, b) => a + b, 0);
  const critical = days.reduce((a, d) => a + d.critical, 0);
  const busiest = totals.indexOf(Math.max(...totals));
  const facts = [
    [count(week), "threats this week"],
    [count(totals[totals.length - 1]), "today"],
    [count(critical), "critical"],
    [week ? days[busiest].label : "—", week ? `busiest day (${totals[busiest]})` : "busiest day"],
  ];
  replaceIfChanged($("chart-facts"), JSON.stringify(facts), () => facts.map(([value, label]) => el("div", {}, [
    el("b", { text: value }),
    el("span", { text: label }),
  ])));
  const rows = [...byType.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const top = rows.length ? rows[0][1] : 1;
  replaceIfChanged($("by-type"), JSON.stringify(rows), () => (rows.length ? rows.map(([type, n]) => {
    const bar = el("i");
    bar.style.setProperty("--w", `${Math.max(6, (n / top) * 100)}%`);
    if (TYPE_COLOURS[type]) bar.style.setProperty("--bar", TYPE_COLOURS[type]);
    const button = el("button", { title: `${TYPE_NOTES[type] || type} Click to see these events.`, attrs: { type: "button" } }, [
      el("span", { text: type }), el("b", { text: String(n) }), bar,
    ]);
    button.addEventListener("click", () => openActivity({ type }));
    return el("li", {}, [button]);
  }) : [el("li", { className: "none", text: "No threats in the last 7 days." })]));
}

function renderOffline(reason) {
  $("top-status-dot").className = "dot bad";
  $("top-status-text").textContent = "Unprotected";
  $("service-dot").className = "dot";
  $("service-text").textContent = "Daemon Offline";
  $("protection-dot").className = "dot bad";
  $("protection-text").textContent = reason;
  setRing(0, "bad");
  $("protection-detail").textContent = "Without the background service nothing is being checked.";
  replaceIfChanged($("score-items"), "offline", () => [el("li", { className: "no", text: "Background service unavailable" })]);
  $("service-state").className = "pill status red";
  $("service-state").textContent = "Unavailable";
  renderToggles(null, false);
  for (const id of ["quick-scan", "verify-canaries", "install-service", "uninstall-service"]) $(id).disabled = true;
}

function matchesQuery(...fields) {
  if (!state.query) return true;
  const query = state.query.toLowerCase();
  return fields.some((field) => String(field || "").toLowerCase().includes(query));
}

// Rebuilding rows on every 2 s poll would swallow clicks that straddle a rebuild, so only
// replace a table body when what it shows has changed.
function replaceIfChanged(node, signature, build) {
  if (node.dataset.signature === signature) return;
  node.dataset.signature = signature;
  node.replaceChildren(...build());
}

function renderCanaries(canaries) {
  const shown = canaries.filter((c) => matchesQuery(c.path, c.state));
  replaceIfChanged($("canary-rows"), JSON.stringify(shown.map((c) => [c.path, c.state])), () => shown.map((c) => el("tr", {}, [
    el("td", { text: c.path, title: c.path }),
    el("td", {}, [el("span", { className: c.state === "Intact" ? "pill green" : "pill red", text: c.state })]),
  ])));
  $("canary-empty").hidden = shown.length > 0;
}

function confirming(action, id) {
  return state.confirm && state.confirm.action === action && state.confirm.id === id && Date.now() < state.confirm.until;
}

function quarantineButton(action, label, id) {
  const armed = confirming(action, id);
  const button = el("button", {
    className: action === "delete" ? "btn btn-small btn-danger" : "btn btn-small",
    text: armed ? `Confirm ${label.toLowerCase()}` : label,
  });
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    quarantineAction(action, id);
  });
  return button;
}

const FILE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9.5 12.5l5 5M14.5 12.5l-5 5"/></svg>';

function quarantineRows(q) {
  const open = state.openQuarantine === q.id;
  const icon = el("span", { className: "file-icon" });
  icon.innerHTML = FILE_ICON;
  const cells = [
    el("td", { title: q.original_path }, [
      el("div", { className: "file-cell" }, [icon, el("span", {}, [
        el("span", { className: "cell-main", text: fileName(q.original_path) }),
        el("span", { className: "cell-sub", text: folderOf(q.original_path) || "—" }),
      ])]),
    ]),
    el("td", { title: q.details }, [
      el("span", { className: typeClass(q.threat_type), text: q.threat_type }),
      el("span", { className: "cell-sub", text: q.details }),
    ]),
    el("td", { text: formatBytes(q.size) }),
    el("td", { title: formatDateTime(q.quarantined_at) }, [
      el("span", { className: "cell-main", text: formatShortDate(q.quarantined_at) }),
      el("span", { className: "cell-sub", text: relativeTime(q.quarantined_at) }),
    ]),
    el("td", { className: "right" }, [
      el("div", { className: "button-group", attrs: { style: "justify-content:flex-end;align-items:center" } }, [
        quarantineButton("restore", "Restore", q.id),
        quarantineButton("delete", "Delete", q.id),
        chevron(),
      ]),
    ]),
  ];
  const detail = detailGrid([
    ["Found at", q.original_path, q.original_path],
    ["Why", q.details],
    ["Size", `${formatBytes(q.size)} (${count(q.size)} bytes)`],
    ["SHA-256", q.sha256, q.sha256],
    ["Quarantined", `${formatDateTime(q.quarantined_at)} (${relativeTime(q.quarantined_at)})`],
    ["Stored as", q.quarantined_path],
    ["Quarantine ID", q.id],
  ], `${TYPE_NOTES[q.threat_type] ? `${TYPE_NOTES[q.threat_type]} ` : ""}The file is locked away and cannot run. Restore puts it back where it was found; Delete removes it for good.`);
  return expandable(cells, detail, open, () => {
    state.openQuarantine = open ? null : q.id;
    renderQuarantine();
  }, 5);
}

function renderQuarantineFacts(all) {
  const total = all.reduce((sum, q) => sum + (Number(q.size) || 0), 0);
  const newest = all.reduce((best, q) => (!best || q.quarantined_at > best.quarantined_at ? q : best), null);
  const types = new Map();
  for (const q of all) types.set(q.threat_type, (types.get(q.threat_type) || 0) + 1);
  const top = [...types.entries()].sort((a, b) => b[1] - a[1])[0];
  const facts = [
    [count(all.length), `file${all.length === 1 ? "" : "s"} held`],
    [formatBytes(total), "total size"],
    [newest ? relativeTime(newest.quarantined_at) : "—", "last file stopped"],
    [top ? top[0] : "—", top ? `most common (${top[1]})` : "most common threat"],
  ];
  replaceIfChanged($("quarantine-facts"), JSON.stringify(facts), () => facts.map(([value, label]) => el("div", {}, [
    el("b", { className: "mono", text: value }),
    el("span", { text: label }),
  ])));
}

function renderQuarantine() {
  const records = state.quarantine.filter((q) => matchesQuery(q.id, q.original_path, q.sha256, q.threat_type, q.details));
  const signature = JSON.stringify([state.openQuarantine, records.map((q) => [q.id, confirming("restore", q.id), confirming("delete", q.id)])]);
  replaceIfChanged($("quarantine-rows"), signature, () => records.flatMap(quarantineRows));
  renderQuarantineFacts(state.quarantine);
  $("quarantine-empty").hidden = records.length > 0;
  $("quarantine-count").textContent = `${state.quarantine.length} file${state.quarantine.length === 1 ? "" : "s"} · click a row for details`;
}

async function quarantineAction(action, id) {
  if (!confirming(action, id)) {
    state.confirm = { action, id, until: Date.now() + CONFIRM_MS };
    renderQuarantine();
    setTimeout(renderQuarantine, CONFIRM_MS + 50);
    return;
  }
  state.confirm = null;
  try {
    const message = await call(action === "restore" ? "restore_quarantine" : "delete_quarantine", { id });
    notice(message, false);
  } catch (error) {
    notice(errorText(error), true);
  }
  await refresh(true);
}

async function loadEvents() {
  const overview = await call("get_events", { limit: OVERVIEW_EVENTS, query: state.query || null, severity: "ALL" });
  const eventsSignature = (events) => events.map((e) => `${e.id}|${e.timestamp}`).join(",");
  replaceIfChanged($("overview-events"), eventsSignature(overview), () => overview.map((e) => eventRow(e)));
  $("overview-empty").hidden = overview.length > 0;
  if (state.page === "activity") {
    const fetched = await call("get_events", { limit: 1000, query: state.query || null, severity: "ALL" });
    const all = fetched.filter((e) => {
      if (state.activityType && e.threat_type !== state.activityType) return false;
      if (state.activityDay !== null) {
        const t = Date.parse(e.timestamp);
        if (t < state.activityDay || t >= state.activityDay + DAY_MS) return false;
      }
      return true;
    });
    renderActivityFilters();
    const counts = { ALL: all.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const e of all) counts[severityKey(e.severity)] = (counts[severityKey(e.severity)] || 0) + 1;
    for (const [key, value] of Object.entries(counts)) {
      const holder = $(`count-${key}`);
      if (holder) holder.textContent = count(value);
    }
    const shown = state.severity === "ALL" ? all : all.filter((e) => severityKey(e.severity) === state.severity);
    $("activity-range").textContent = all.length
      ? `Newest ${relativeTime(all[0].timestamp)} · oldest ${formatWhen(all[all.length - 1].timestamp)} · click a row for details`
      : "";
    replaceIfChanged($("activity-events"), `${eventsSignature(shown)}|${state.openEvent}`, () => shown.flatMap(activityRows));
    $("activity-empty").hidden = shown.length > 0;
  }
}

async function refresh(force) {
  if (state.refreshing && !force) return;
  state.refreshing = true;
  try {
    state.dashboard = await call("get_dashboard_state");
    renderDashboard(state.dashboard);
    for (const id of ["quick-scan", "verify-canaries", "install-service"]) {
      if (!$(id).dataset.busy) $(id).disabled = false;
    }
    await loadEvents();
    if (state.page === "overview") await loadChart(force);
    state.quarantine = await call("list_quarantine").catch((error) => {
      if (state.page === "quarantine") notice(errorText(error), true);
      return state.quarantine;
    });
    renderQuarantine();
  } catch (error) {
    renderOffline(invoke ? `Unavailable — ${errorText(error)}` : "Open The Nex from its desktop app to manage protection.");
  } finally {
    state.refreshing = false;
  }
}

async function busy(buttonId, label, work) {
  const button = $(buttonId);
  const original = button.innerHTML; // static markup (label and icon), restored as it was
  button.dataset.busy = "1";
  button.disabled = true;
  button.textContent = label;
  try {
    await work();
  } catch (error) {
    notice(errorText(error), true);
  } finally {
    delete button.dataset.busy;
    button.disabled = false;
    button.innerHTML = original;
    await refresh(true);
  }
}

/* ---- Quick scan: a running sheet with a radar, then the result ------------------------------ */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const MIN_SCAN_SHOW_MS = 1600; // a very fast scan still shows the animation long enough to read
const scanUi = { ticker: 0, hideTimer: 0 };

function hideScanSheet() {
  clearTimeout(scanUi.hideTimer);
  $("scan-sheet").hidden = true;
}

function setScanSheet(stateName, title, detail) {
  const sheet = $("scan-sheet");
  sheet.dataset.state = stateName;
  $("scan-title").textContent = title;
  $("scan-detail").textContent = detail;
}

async function runQuickScan() {
  if (state.scanning) return;
  state.scanning = true;
  clearTimeout(scanUi.hideTimer);
  const button = $("quick-scan");
  button.classList.add("scanning");
  button.dataset.busy = "1"; // the 2 s refresh leaves a busy button alone
  button.disabled = true;
  button.querySelector(".scan-label").textContent = "Scanning…";
  $("hero").classList.add("scanning");
  document.querySelector(".main").classList.add("scanning");
  const sheet = $("scan-sheet");
  $("scan-findings").replaceChildren();
  $("scan-view").hidden = true;
  $("scan-close").hidden = true;
  const roots = (state.dashboard && state.dashboard.watched_dirs) || [];
  setScanSheet("running", "Quick scan running", roots.length ? `Checking ${roots[0]}…` : "Checking your watched folders…");
  sheet.hidden = false;
  const started = performance.now();
  let rootIndex = 0;
  let lastSwitch = started;
  scanUi.ticker = setInterval(() => {
    const now = performance.now();
    $("scan-time").textContent = `${((now - started) / 1000).toFixed(1)} s`;
    if (roots.length > 1 && now - lastSwitch > 650) {
      lastSwitch = now;
      rootIndex = (rootIndex + 1) % roots.length;
      $("scan-detail").textContent = `Checking ${roots[rootIndex]}… (${rootIndex + 1} of ${roots.length} folders)`;
    }
  }, 100);

  let report = null;
  let failure = null;
  try {
    report = await call("run_quick_scan");
  } catch (error) {
    failure = error;
  }
  const shown = performance.now() - started;
  if (shown < MIN_SCAN_SHOW_MS) await sleep(MIN_SCAN_SHOW_MS - shown);
  clearInterval(scanUi.ticker);

  button.classList.remove("scanning");
  delete button.dataset.busy;
  button.disabled = false;
  button.querySelector(".scan-label").textContent = "Quick Scan";
  $("hero").classList.remove("scanning");
  document.querySelector(".main").classList.remove("scanning");
  state.scanning = false;
  $("scan-close").hidden = false;

  if (failure) {
    setScanSheet("error", "The scan could not run", errorText(failure));
  } else {
    const threats = report.findings.length;
    const seconds = ((report.duration_ms || 0) / 1000).toFixed(1);
    $("scan-time").textContent = `${seconds} s`;
    const folders = report.roots.length;
    const notes = [
      `${count(report.files_scanned)} of ${count(report.files_examined)} files inspected in ${seconds} s across ${folders} folder${folders === 1 ? "" : "s"}`,
      report.dry_run ? "dry run: nothing was moved" : "",
      report.truncated ? "stopped at the file limit" : "",
    ].filter(Boolean).join(" · ");
    if (threats) {
      setScanSheet("bad", `Scan found ${threats} threat${threats === 1 ? "" : "s"}`, notes);
      $("scan-findings").replaceChildren(...report.findings.slice(0, 5).map((f) => el("li", {}, [
        el("span", { className: typeClass(f.threat_type), text: f.threat_type }),
        el("span", { text: `${fileName(f.path)} · ${f.detail}`, title: f.path }),
      ])));
      $("scan-view").hidden = false;
    } else {
      setScanSheet("ok", "Scan complete: no threats found", notes);
      $("hero").classList.add("scan-done");
      setTimeout(() => $("hero").classList.remove("scan-done"), 1000);
      scanUi.hideTimer = setTimeout(hideScanSheet, 9000);
    }
  }
  await refresh(true);
}

/** Slides the sidebar highlight onto the active page's item. */
function moveNavIndicator() {
  const indicator = $("nav-indicator");
  const active = document.querySelector(".nav-item.active");
  if (!indicator || !active) return;
  indicator.style.transform = `translateY(${active.offsetTop}px)`;
  indicator.style.height = `${active.offsetHeight}px`;
  if (!indicator.classList.contains("ready")) {
    // first placement: appear in place instead of sliding in from the top
    requestAnimationFrame(() => indicator.classList.add("ready"));
  }
}

function showPage(page) {
  state.page = page;
  for (const item of document.querySelectorAll(".nav-item")) item.classList.toggle("active", item.dataset.page === page);
  moveNavIndicator();
  for (const section of document.querySelectorAll(".page")) section.classList.toggle("active", section.id === `page-${page}`);
  $("page-title").textContent = PAGE_TITLES[page];
  $("page-sub").textContent = page === "overview" ? greeting() : PAGE_SUBS[page] || "";
  $("search-box").hidden = !SEARCH_PAGES.has(page);
  // The AegisMesh console loads on first visit only (it can open the camera).
  const frame = $("aegismesh-frame");
  if (page === "aegismesh" && frame && !frame.getAttribute("src")) frame.setAttribute("src", "aegismesh/index.html");
  refresh(true);
}

async function toggleEngine(button) {
  const engine = button.dataset.engine;
  const enabled = button.getAttribute("aria-checked") !== "true";
  state.pendingToggles.add(engine);
  for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) setSwitch(twin, enabled);
  try {
    const toggles = await call("toggle_engine", { engine, enabled });
    state.pendingToggles.delete(engine);
    renderToggles(toggles, true);
  } catch (error) {
    state.pendingToggles.delete(engine);
    for (const twin of document.querySelectorAll(`.switch[data-engine="${engine}"]`)) setSwitch(twin, !enabled);
    notice(errorText(error), true);
  }
  await refresh(true);
}

function wire() {
  buildEngineRows();
  for (const item of document.querySelectorAll(".nav-item")) item.addEventListener("click", () => showPage(item.dataset.page));
  // Anything with data-goto opens that page (tiles, engine cards, score items, links); a switch
  // inside a card still only toggles. data-focus also highlights one engine on the Engines page.
  const go = (target) => {
    if (target.dataset.goto === "activity") openActivity();
    else showPage(target.dataset.goto);
    if (target.dataset.focus) focusEngine(target.dataset.focus);
  };
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-goto]");
    if (target && !event.target.closest(".switch")) go(target);
  });
  document.addEventListener("keydown", (event) => {
    const target = event.target.closest && event.target.closest(".engine-card[data-goto]");
    if (target && event.target === target && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      go(target);
    }
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".switch[data-engine]");
    if (button && !button.disabled) toggleEngine(button);
  });
  for (const pill of document.querySelectorAll(".pill-filter")) {
    pill.addEventListener("click", () => {
      state.severity = pill.dataset.severity;
      for (const other of document.querySelectorAll(".pill-filter")) other.classList.toggle("active", other === pill);
      refresh(true);
    });
  }

  const search = $("search");
  let searchTimer = null;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = search.value.trim();
      refresh(true);
    }, 150);
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      search.value = "";
      state.query = "";
      search.blur();
      refresh(true);
    }
  });
  const mac = /Mac/i.test(navigator.platform || navigator.userAgent);
  $("search-hint").textContent = mac ? "⌘ K" : "Ctrl K";
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      search.focus();
      search.select();
    }
  });

  $("quick-scan").addEventListener("click", runQuickScan);
  $("scan-close").addEventListener("click", hideScanSheet);
  $("scan-view").addEventListener("click", () => { hideScanSheet(); openActivity(); });
  $("verify-canaries").addEventListener("click", () => busy("verify-canaries", "Verifying…", async () => {
    const canaries = await call("verify_canaries");
    const intact = canaries.filter((c) => c.state === "Intact").length;
    notice(`${intact} of ${canaries.length} canary files intact.`, intact !== canaries.length);
  }));
  $("install-service").addEventListener("click", () => busy("install-service", "Installing…", async () => {
    notice(await call("install_service"), false);
  }));
  $("uninstall-service").addEventListener("click", () => busy("uninstall-service", "Removing…", async () => {
    notice(await call("uninstall_service"), false);
  }));
}

/* ---- Appearance: wallpaper layer + glass theme ------------------------------------------- */

const APPEARANCE_KEY = "thenex.appearance";
const DEFAULT_APPEARANCE = Object.freeze({ wallpaper_source: "preset:aurora", bg_dim: 0.2, card_blur: 18, card_alpha: 0.62 });
// Before 0.3.1 the default was Matte Dark; a look still exactly on that old default was never
// customised, so it moves to the new default.
const OLD_DEFAULT = Object.freeze({ wallpaper_source: "preset:matte", bg_dim: 0.65, card_blur: 14, card_alpha: 0.72 });
const MAX_WALLPAPER_BYTES = 25 * 1024 * 1024;
const WALLPAPER_FILE_NAME = /\.(png|jpe?g|webp|gif)$/i;
const WALLPAPER_MIME = /^image\/(png|jpeg|webp|gif)$/;
const VALID_SOURCE = /^(preset:(aurora|matte|crimson|cyberhex)|url:https?:\/\/\S+|file:wallpaper-[A-Za-z0-9-]+\.(png|jpe?g|webp|gif))$/i;
const SAVE_DELAY_MS = 350;
const IMAGE_TIMEOUT_MS = 20000;

const CRIMSON_CSS = [
  "radial-gradient(120% 80% at 76% 14%, rgba(239, 68, 68, 0.55) 0%, rgba(127, 29, 29, 0.32) 32%, transparent 62%)",
  "radial-gradient(90% 70% at 14% 92%, rgba(153, 27, 27, 0.55) 0%, transparent 62%)",
  "radial-gradient(55% 45% at 52% 56%, rgba(76, 5, 25, 0.85) 0%, transparent 72%)",
  "linear-gradient(160deg, #1d0508 0%, #0b0608 55%, #050506 100%)",
].join(", ");

// Pointy-top honeycomb: one 60 x 103.92 tile holds a hexagon plus the stub to the row below.
function hexVertex(i, j, corner) {
  const offsets = { t: [30, 0], ur: [60, 17.32], lr: [60, 51.96], b: [30, 69.28], ll: [0, 51.96], ul: [0, 17.32], s: [30, 103.92] };
  const [dx, dy] = offsets[corner];
  return `${(60 * i + dx).toFixed(2)},${(103.92 * j + dy).toFixed(2)}`;
}

function cyberHexCss() {
  const amber = "#F5A524";
  const cyan = "#38BDF8";
  const traces = [
    [amber, [[3, 1, "ul"], [3, 1, "t"], [3, 1, "ur"], [3, 1, "lr"], [3, 1, "b"], [3, 1, "s"]]],
    [cyan, [[9, 3, "ll"], [9, 3, "ul"], [9, 3, "t"], [9, 3, "ur"]]],
    [amber, [[17, 6, "t"], [17, 6, "ur"], [17, 6, "lr"], [17, 6, "b"], [17, 6, "ll"]]],
    [cyan, [[24, 2, "b"], [24, 2, "s"], [24, 3, "ur"], [24, 3, "lr"]]],
    [amber, [[28, 7, "ul"], [28, 7, "t"], [28, 7, "ur"]]],
    [cyan, [[12, 8, "lr"], [12, 8, "b"], [12, 8, "ll"], [12, 8, "ul"]]],
    [amber, [[30, 0, "ll"], [30, 0, "b"], [30, 0, "s"]]],
    [cyan, [[6, 7, "t"], [6, 7, "ur"], [6, 7, "lr"]]],
  ];
  const lines = traces.map(([color, points]) => {
    const pts = points.map(([i, j, corner]) => hexVertex(i, j, corner)).join(" ");
    return `<polyline points='${pts}' stroke='${color}' stroke-width='6' stroke-opacity='.45' filter='url(#g)'/>` +
      `<polyline points='${pts}' stroke='${color}' stroke-width='1.6'/>`;
  }).join("");
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1920 1080' preserveAspectRatio='xMidYMid slice'>" +
    "<defs>" +
    "<radialGradient id='a' cx='22%' cy='18%' r='62%'><stop offset='0' stop-color='#0E3A4A' stop-opacity='.9'/><stop offset='1' stop-color='#05080D' stop-opacity='0'/></radialGradient>" +
    "<radialGradient id='b' cx='86%' cy='88%' r='55%'><stop offset='0' stop-color='#3D2A08' stop-opacity='.85'/><stop offset='1' stop-color='#05080D' stop-opacity='0'/></radialGradient>" +
    "<pattern id='h' width='60' height='103.92' patternUnits='userSpaceOnUse'><path d='M30 0L60 17.32V51.96L30 69.28L0 51.96V17.32ZM30 69.28V103.92' fill='none' stroke='#7DD3FC' stroke-opacity='.16' stroke-width='1.2'/></pattern>" +
    "<filter id='g' x='-10%' y='-10%' width='120%' height='120%'><feGaussianBlur stdDeviation='4'/></filter>" +
    "</defs>" +
    "<rect width='1920' height='1080' fill='#05080D'/><rect width='1920' height='1080' fill='url(#a)'/>" +
    "<rect width='1920' height='1080' fill='url(#b)'/><rect width='1920' height='1080' fill='url(#h)'/>" +
    `<g fill='none' stroke-linecap='round' stroke-linejoin='round'>${lines}</g></svg>`;
  return `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
}

// Deep navy (or, in light mode, pale sky) with blue, violet and teal glows and two soft
// light streaks.
function auroraCss(light) {
  const base = light ? ["#F7F9FF", "#EEF2FC", "#E6ECFA"] : ["#0C1333", "#070A1B", "#04060E"];
  const glow = light ? [".45", ".38", ".30", ".16"] : [".55", ".5", ".26", ".16"];
  const svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1600 900' preserveAspectRatio='xMidYMid slice'>" +
    "<defs>" +
    `<linearGradient id='bg' x1='0' y1='0' x2='.4' y2='1'><stop offset='0' stop-color='${base[0]}'/><stop offset='.55' stop-color='${base[1]}'/><stop offset='1' stop-color='${base[2]}'/></linearGradient>` +
    `<radialGradient id='g1' cx='8%' cy='0%' r='55%'><stop offset='0' stop-color='${light ? "#9DB8FF" : "#4F7BFF"}' stop-opacity='${glow[0]}'/><stop offset='1' stop-color='#4F7BFF' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g2' cx='96%' cy='8%' r='48%'><stop offset='0' stop-color='${light ? "#CBB4FF" : "#9B6BFF"}' stop-opacity='${glow[1]}'/><stop offset='1' stop-color='#9B6BFF' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g3' cx='82%' cy='100%' r='50%'><stop offset='0' stop-color='${light ? "#8EEBD9" : "#2EE6C5"}' stop-opacity='${glow[2]}'/><stop offset='1' stop-color='#2EE6C5' stop-opacity='0'/></radialGradient>` +
    `<radialGradient id='g4' cx='12%' cy='96%' r='40%'><stop offset='0' stop-color='${light ? "#FFB3D1" : "#FF5FA2"}' stop-opacity='${glow[3]}'/><stop offset='1' stop-color='#FF5FA2' stop-opacity='0'/></radialGradient>` +
    "<linearGradient id='s1' x1='0' x2='1'><stop offset='0' stop-color='#5B8CFF' stop-opacity='0'/><stop offset='.45' stop-color='#7A6BFF' stop-opacity='.85'/><stop offset='.75' stop-color='#C46BFF' stop-opacity='.6'/><stop offset='1' stop-color='#C46BFF' stop-opacity='0'/></linearGradient>" +
    "<linearGradient id='s2' x1='0' x2='1'><stop offset='0' stop-color='#2EE6C5' stop-opacity='0'/><stop offset='.5' stop-color='#4FC3FF' stop-opacity='.7'/><stop offset='1' stop-color='#5B8CFF' stop-opacity='0'/></linearGradient>" +
    "<filter id='w' x='-20%' y='-50%' width='140%' height='200%'><feGaussianBlur stdDeviation='26'/></filter>" +
    "<filter id='n' x='-10%' y='-50%' width='120%' height='200%'><feGaussianBlur stdDeviation='2.2'/></filter>" +
    "</defs>" +
    "<rect width='1600' height='900' fill='url(#bg)'/>" +
    "<rect width='1600' height='900' fill='url(#g1)'/><rect width='1600' height='900' fill='url(#g2)'/>" +
    "<rect width='1600' height='900' fill='url(#g3)'/><rect width='1600' height='900' fill='url(#g4)'/>" +
    "<g fill='none' stroke-linecap='round'>" +
    "<path d='M-120 760C260 560 620 860 980 600S1500 260 1760 300' stroke='url(#s1)' stroke-width='90' opacity='.35' filter='url(#w)'/>" +
    "<path d='M-120 760C260 560 620 860 980 600S1500 260 1760 300' stroke='url(#s1)' stroke-width='3' opacity='.8' filter='url(#n)'/>" +
    "<path d='M-120 800C300 620 640 900 1000 650S1520 330 1760 360' stroke='url(#s1)' stroke-width='1.5' opacity='.55' filter='url(#n)'/>" +
    "<path d='M-80 880C360 720 760 820 1120 700S1500 560 1720 520' stroke='url(#s2)' stroke-width='70' opacity='.22' filter='url(#w)'/>" +
    "<path d='M-80 880C360 720 760 820 1120 700S1500 560 1720 520' stroke='url(#s2)' stroke-width='2' opacity='.6' filter='url(#n)'/>" +
    "</g></svg>";
  return `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
}

const PRESETS = [
  { id: "aurora", label: "Aurora", css: () => auroraCss(isLight()) },
  {
    id: "matte",
    label: "Matte",
    css: "none",
    swatch: () => (isLight() ? "linear-gradient(135deg, #FFFFFF 0%, #E6ECFA 100%)" : "linear-gradient(135deg, #141A2E 0%, #060914 100%)"),
  },
  { id: "crimson", label: "Crimson Abyss", css: CRIMSON_CSS },
  { id: "cyberhex", label: "Cyber Hex", css: cyberHexCss() },
];

const look = { current: { ...DEFAULT_APPEARANCE }, css: "none", previewUrl: null, saveTimer: null };

function clampNumber(value, low, high, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(high, Math.max(low, number)) : fallback;
}

function isOldDefault(a) {
  return a && Object.keys(OLD_DEFAULT).every((key) => a[key] === OLD_DEFAULT[key]);
}

function normalizeAppearance(value) {
  const a = value && typeof value === "object" ? (isOldDefault(value) ? DEFAULT_APPEARANCE : value) : {};
  const source = typeof a.wallpaper_source === "string" && VALID_SOURCE.test(a.wallpaper_source)
    ? a.wallpaper_source
    : DEFAULT_APPEARANCE.wallpaper_source;
  return {
    wallpaper_source: source,
    bg_dim: clampNumber(a.bg_dim, 0, 0.9, DEFAULT_APPEARANCE.bg_dim),
    card_blur: clampNumber(a.card_blur, 0, 24, DEFAULT_APPEARANCE.card_blur),
    card_alpha: clampNumber(a.card_alpha, 0.3, 0.95, DEFAULT_APPEARANCE.card_alpha),
  };
}

// Quoted CSS url(); quotes, backslashes and line breaks are escaped so a URL cannot break out.
function cssUrl(url) {
  return `url("${String(url).replace(/["\\\n\r\f]/g, (c) => `\\${c.charCodeAt(0).toString(16)} `)}")`;
}

function fileWallpaperUrl(name) {
  const convert = tauri && tauri.core && tauri.core.convertFileSrc;
  return typeof convert === "function" ? convert(name, "wallpaper") : null;
}

function imageSource(source) {
  if (source.startsWith("url:")) return source.slice(4);
  if (source.startsWith("file:")) return fileWallpaperUrl(source.slice(5));
  return null;
}

const resolve = (value) => (typeof value === "function" ? value() : value);

function wallpaperCss(source) {
  if (source.startsWith("preset:")) {
    const preset = PRESETS.find((p) => p.id === source.slice(7));
    return preset ? resolve(preset.css) : "none";
  }
  const src = imageSource(source);
  return src ? cssUrl(src) : "none";
}

function wallpaperLabel(source) {
  if (look.previewUrl) return "Preview · not saved";
  if (source.startsWith("preset:")) {
    const preset = PRESETS.find((p) => p.id === source.slice(7));
    return preset ? preset.label : "Preset";
  }
  if (source.startsWith("file:")) return "Custom image";
  try {
    return new URL(source.slice(4)).hostname;
  } catch {
    return "Web image";
  }
}

function readMirror() {
  try {
    return JSON.parse(localStorage.getItem(APPEARANCE_KEY) || "null");
  } catch {
    return null;
  }
}

function writeMirror(appearance, css) {
  try {
    localStorage.setItem(APPEARANCE_KEY, JSON.stringify({ ...appearance, css }));
  } catch {
    /* storage full or disabled: settings.json still has it */
  }
}

function setSlider(id, value, text) {
  const input = $(id);
  if (document.activeElement !== input) input.value = String(value);
  $(`${id}-value`).textContent = text;
}

function updateAppearanceControls() {
  const a = look.current;
  setSlider("bg-dim", Math.round(a.bg_dim * 100), `${Math.round(a.bg_dim * 100)}%`);
  setSlider("card-blur", Math.round(a.card_blur), `${Math.round(a.card_blur)}px`);
  setSlider("card-alpha", Math.round(a.card_alpha * 100), `${Math.round(a.card_alpha * 100)}%`);
  for (const chip of document.querySelectorAll(".preset")) {
    const active = !look.previewUrl && a.wallpaper_source === `preset:${chip.dataset.preset}`;
    chip.setAttribute("aria-pressed", active ? "true" : "false");
  }
  $("wallpaper-label").textContent = wallpaperLabel(a.wallpaper_source);
}

function applyAppearance(appearance, css) {
  const style = document.documentElement.style;
  style.setProperty("--bg-dim", String(appearance.bg_dim));
  style.setProperty("--card-blur", `${appearance.card_blur}px`);
  style.setProperty("--card-alpha", String(appearance.card_alpha));
  style.setProperty("--wallpaper", css);
  look.current = appearance;
  look.css = css;
  if (!look.previewUrl) writeMirror(appearance, css);
  updateAppearanceControls();
  applyAmbient();
}

/* ---- Motion: drifting background, a glow that follows the mouse --------------------------- */

const AMBIENT_KEY = "thenex.ambient";
const reducedMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

function ambientWanted() {
  try {
    return localStorage.getItem(AMBIENT_KEY) !== "off";
  } catch {
    return true;
  }
}

/** The drifting colour shows over the app's own wallpapers, never over a photo you chose. */
function applyAmbient() {
  const source = (look.current && look.current.wallpaper_source) || "";
  const ownWallpaper = !look.previewUrl && /^preset:(aurora|matte)$/.test(source);
  const on = ambientWanted() && ownWallpaper && !(reducedMotion && reducedMotion.matches);
  document.documentElement.dataset.ambient = on ? "on" : "off";
  const toggle = $("ambient-switch");
  if (toggle) toggle.setAttribute("aria-checked", String(ambientWanted()));
}

function wireMotion() {
  $("ambient-switch").addEventListener("click", () => {
    try {
      localStorage.setItem(AMBIENT_KEY, ambientWanted() ? "off" : "on");
    } catch {
      /* storage disabled: nothing to remember */
    }
    applyAmbient();
  });
  if (reducedMotion && reducedMotion.addEventListener) reducedMotion.addEventListener("change", applyAmbient);

  // The glass under the mouse gets a soft light at the pointer (CSS reads --mx and --my).
  const GLASS = ".sidebar, .topbar, .panel, .hero, .stat, .aegis-tile";
  let pending = null;
  document.addEventListener("pointermove", (event) => {
    if (pending === null) {
      requestAnimationFrame(() => {
        const target = pending.target && pending.target.closest ? pending.target.closest(GLASS) : null;
        if (target) {
          const box = target.getBoundingClientRect();
          target.style.setProperty("--mx", `${Math.round(pending.clientX - box.left)}px`);
          target.style.setProperty("--my", `${Math.round(pending.clientY - box.top)}px`);
        }
        pending = null;
      });
    }
    pending = event;
  }, { passive: true });

  document.querySelector(".nav").classList.add("has-indicator");
  moveNavIndicator();
  window.addEventListener("resize", moveNavIndicator);
}

function appearanceStatus(text, kind) {
  const status = $("appearance-status");
  status.textContent = text;
  status.className = `small ${kind || "muted"}`;
}

function sentence(text) {
  const value = String(text || "");
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

async function persistAppearance() {
  if (!invoke) return;
  try {
    const saved = normalizeAppearance(await call("save_appearance", { appearance: look.current }));
    if (saved.wallpaper_source !== look.current.wallpaper_source) applyAppearance(saved, wallpaperCss(saved.wallpaper_source));
  } catch (error) {
    appearanceStatus(`Could not save the appearance: ${errorText(error)}`, "error");
  }
}

function schedulePersist() {
  clearTimeout(look.saveTimer);
  look.saveTimer = setTimeout(persistAppearance, SAVE_DELAY_MS);
}

function clearPreview() {
  if (look.previewUrl) URL.revokeObjectURL(look.previewUrl);
  look.previewUrl = null;
}

function commitAppearance(appearance) {
  clearPreview();
  const next = normalizeAppearance(appearance);
  applyAppearance(next, wallpaperCss(next.wallpaper_source));
  schedulePersist();
}

function loadImage(src) {
  return new Promise((resolve, reject) => {
    if (!src) {
      reject(new Error("this wallpaper needs The Nex desktop app"));
      return;
    }
    const image = new Image();
    const timer = setTimeout(() => reject(new Error("the image took too long to load")), IMAGE_TIMEOUT_MS);
    image.onload = () => { clearTimeout(timer); resolve(); };
    image.onerror = () => { clearTimeout(timer); reject(new Error("the image could not be displayed (the site may block embedding)")); };
    image.src = src;
  });
}

const APPEARANCE_CONTROLS = ["apply-wallpaper-url", "choose-wallpaper-file", "reset-appearance", "wallpaper-url"];

async function withAppearanceBusy(label, work) {
  const controls = [...APPEARANCE_CONTROLS.map($), ...document.querySelectorAll(".preset")];
  for (const control of controls) control.disabled = true;
  appearanceStatus(label, "muted");
  try {
    await work();
  } catch (error) {
    appearanceStatus(sentence(errorText(error)), "error");
  } finally {
    for (const control of controls) control.disabled = false;
  }
}

function applyWallpaperUrl() {
  const input = $("wallpaper-url");
  const raw = input.value.trim();
  if (!raw) {
    appearanceStatus("Paste an image or wallpaper page address first.", "error");
    input.focus();
    return Promise.resolve();
  }
  return withAppearanceBusy("Fetching wallpaper…", async () => {
    let imageUrl = raw;
    if (invoke) imageUrl = await call("resolve_wallpaper_url", { url: raw });
    else if (!/^https?:\/\/\S+$/i.test(raw)) throw new Error("enter a full http:// or https:// address");
    let source = `url:${imageUrl}`;
    let note = "";
    if (invoke) {
      try {
        source = `file:${await call("download_wallpaper", { url: imageUrl })}`;
        note = " · saved for offline use";
      } catch {
        note = " · loaded from the web";
      }
    }
    await loadImage(imageSource(source));
    commitAppearance({ ...look.current, wallpaper_source: source });
    input.value = "";
    appearanceStatus(`Wallpaper applied${note}.`, "ok");
  });
}

function applyWallpaperFile(file) {
  if (!file) return Promise.resolve();
  return withAppearanceBusy("Saving image…", async () => {
    if (!WALLPAPER_FILE_NAME.test(file.name) && !WALLPAPER_MIME.test(file.type)) throw new Error("choose a PNG, JPG, WEBP or GIF image");
    if (file.size > MAX_WALLPAPER_BYTES) throw new Error("images up to 25 MB are supported");
    if (!invoke) {
      const url = URL.createObjectURL(file);
      await loadImage(url);
      clearPreview();
      look.previewUrl = url;
      applyAppearance(look.current, cssUrl(url));
      appearanceStatus("Previewing only: open The Nex desktop app to keep a local wallpaper.", "ok");
      return;
    }
    // Raw bytes (not JSON) so a 25 MB image is not inflated into a number array.
    const name = await invoke("save_wallpaper_file", new Uint8Array(await file.arrayBuffer()));
    const source = `file:${name}`;
    await loadImage(imageSource(source));
    commitAppearance({ ...look.current, wallpaper_source: source });
    appearanceStatus("Wallpaper applied · stored in the app's data folder.", "ok");
  });
}

function buildPresetChips() {
  $("wallpaper-presets").replaceChildren(...PRESETS.map((preset) => {
    const swatch = el("span", { className: "swatch" });
    swatch.style.backgroundImage = resolve(preset.swatch) || resolve(preset.css);
    const chip = el("button", { className: "preset", attrs: { type: "button", "data-preset": preset.id, "aria-pressed": "false" } }, [
      swatch,
      el("span", { text: preset.label }),
    ]);
    chip.addEventListener("click", () => {
      commitAppearance({ ...look.current, wallpaper_source: `preset:${preset.id}` });
      appearanceStatus(`${preset.label} applied.`, "ok");
    });
    return chip;
  }));
}

function wireAppearance() {
  buildPresetChips();
  const sliders = [
    ["bg-dim", "bg_dim", (value) => value / 100],
    ["card-blur", "card_blur", (value) => value],
    ["card-alpha", "card_alpha", (value) => value / 100],
  ];
  for (const [id, key, scale] of sliders) {
    $(id).addEventListener("input", (event) => {
      const next = normalizeAppearance({ ...look.current, [key]: scale(Number(event.target.value)) });
      applyAppearance(next, look.css);
      if (!look.previewUrl) schedulePersist();
    });
  }
  $("apply-wallpaper-url").addEventListener("click", applyWallpaperUrl);
  $("wallpaper-url").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyWallpaperUrl();
    }
  });
  $("choose-wallpaper-file").addEventListener("click", () => $("wallpaper-file").click());
  $("wallpaper-file").addEventListener("change", (event) => {
    const [file] = event.target.files || [];
    event.target.value = "";
    applyWallpaperFile(file);
  });
  $("reset-appearance").addEventListener("click", () => {
    $("wallpaper-url").value = "";
    commitAppearance({ ...DEFAULT_APPEARANCE });
    appearanceStatus("Default look restored.", "ok");
  });
}

/* ---- Theme: dark, light or match the system ---------------------------------------------- */

const THEME_KEY = "thenex.theme";
const lightQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;

function themePref() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "system" ? value : "dark";
  } catch {
    return "dark";
  }
}

function isLight() {
  const pref = themePref();
  return pref === "light" || (pref === "system" && Boolean(lightQuery && lightQuery.matches));
}

function applyTheme() {
  document.documentElement.dataset.theme = isLight() ? "light" : "dark";
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === themePref()));
  }
  // The app draws its preset wallpapers in a light and a dark version.
  if (!look.previewUrl) applyAppearance(look.current, wallpaperCss(look.current.wallpaper_source));
  buildPresetChips();
  updateAppearanceControls();
}

function setTheme(pref) {
  try {
    localStorage.setItem(THEME_KEY, pref);
  } catch {
    /* storage disabled: the choice lasts until the window closes */
  }
  applyTheme();
}

function wireTheme() {
  $("theme-toggle").addEventListener("click", () => setTheme(isLight() ? "dark" : "light"));
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.addEventListener("click", () => setTheme(button.dataset.themeChoice));
  }
  if (lightQuery && lightQuery.addEventListener) lightQuery.addEventListener("change", () => { if (themePref() === "system") applyTheme(); });
}

async function initAppearance() {
  wireAppearance();
  const start = normalizeAppearance(readMirror() || DEFAULT_APPEARANCE);
  applyAppearance(start, wallpaperCss(start.wallpaper_source));
  if (!invoke) return;
  try {
    const stored = normalizeAppearance(await call("get_appearance"));
    if (JSON.stringify(stored) !== JSON.stringify(start)) applyAppearance(stored, wallpaperCss(stored.wallpaper_source));
  } catch {
    /* keep the mirrored look; settings.json is unreadable right now */
  }
}

wire();
$("page-sub").textContent = greeting();
wireTheme();
wireMotion();
initAppearance().then(applyTheme);
refresh(true);
setInterval(() => refresh(false), REFRESH_MS);
