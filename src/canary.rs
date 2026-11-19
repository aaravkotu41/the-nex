use crate::config::AppConfig;
use crate::logger;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub const CANARY_FILE_NAMES: [&str; 2] = [".thenex_canary_01.docx", ".thenex_canary_02.xlsx"];
pub const SELF_WRITE_COOLDOWN_MS: u64 = 2000;
const CANARY_PREFIX: &str = ".thenex_canary_";
const CANARY_MAGIC: &[u8] = b"THENEX\x00CANARY\x00v1\x00";
const CANARY_LEN: usize = 24 * 1024;
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const HUNT_COOLDOWN: Duration = Duration::from_secs(3);
const HUNT_WINDOW: Duration = Duration::from_millis(300);
const ACTIVE_WRITE_BYTES: u64 = 4096;
const READ_RETRIES: u32 = 3;
const READ_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Heavy writers that are never ransomware suspects on their own.
const SAFE_WRITERS: &[&str] = &[
    "msmpeng.exe",
    "mssense.exe",
    "nissrv.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "onedrive.exe",
    "filecoauth.exe",
    "dropbox.exe",
    "googledrivefs.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "wuauclt.exe",
    "musnotification.exe",
    "msiexec.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "conhost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "smartscreen.exe",
    "securityhealthservice.exe",
    "mds",
    "mds_stores",
    "mdworker",
    "mdworker_shared",
    "mdsync",
    "fseventsd",
    "backupd",
    "backupd-helper",
    "cloudd",
    "bird",
    "fileproviderd",
    "photoanalysisd",
    "softwareupdated",
    "installd",
    "system_installd",
    "syspolicyd",
    "xprotectservice",
    "logd",
];

pub enum CanaryMsg {
    FsEvent(PathBuf),
    SetDirs(Vec<PathBuf>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryState {
    Intact,
    Missing,
    Modified,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterSuspect {
    pub pid: Pid,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub written_bytes: u64,
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn is_canary_path(path: &Path) -> bool {
    path.file_name()
        .map(|n| {
            n.to_string_lossy()
                .to_ascii_lowercase()
                .starts_with(CANARY_PREFIX)
        })
        .unwrap_or(false)
}

pub fn is_safe_writer(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SAFE_WRITERS.contains(&lower.as_str())
}

/// Deterministic per-index body: magic header + xorshift stream, so tampering is a byte compare.
pub fn canary_content(index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANARY_LEN);
    out.extend_from_slice(CANARY_MAGIC);
    out.push(index as u8);
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ ((index as u64 + 1) << 17);
    while out.len() < CANARY_LEN {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(CANARY_LEN);
    out
}

pub fn check_canary(path: &Path, index: usize) -> CanaryState {
    for attempt in 0..READ_RETRIES {
        match fs::read(path) {
            Ok(data) => {
                return if data == canary_content(index) {
                    CanaryState::Intact
                } else {
                    CanaryState::Modified
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return CanaryState::Missing,
            Err(_) if attempt + 1 < READ_RETRIES => thread::sleep(READ_RETRY_DELAY),
            Err(_) => return CanaryState::Unreadable,
        }
    }
    CanaryState::Unreadable
}

pub fn remove_canaries(dirs: &[PathBuf]) -> usize {
    let mut removed = 0;
    for dir in dirs {
        for name in CANARY_FILE_NAMES {
            let path = dir.join(name);
            if path.exists() {
                let _ = quarantine::set_readonly(&path, false);
                if fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

fn dedup_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    dirs.into_iter()
        .filter(|d| seen.insert(platform::path_key(d)))
        .collect()
}

pub struct CanaryManager {
    cfg: Arc<AppConfig>,
    dirs: Vec<PathBuf>,
    deployed: HashSet<String>,
    self_write: Arc<AtomicU64>,
    last_hunt: Option<Instant>,
}

impl CanaryManager {
    pub fn new(cfg: Arc<AppConfig>, dirs: Vec<PathBuf>) -> Self {
        Self {
            cfg,
            dirs: dedup_dirs(dirs),
            deployed: HashSet::new(),
            self_write: Arc::new(AtomicU64::new(0)),
            last_hunt: None,
        }
    }

    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    pub fn self_write_marker(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.self_write)
    }

    pub fn in_cooldown(&self) -> bool {
        now_millis().saturating_sub(self.self_write.load(Ordering::SeqCst)) < SELF_WRITE_COOLDOWN_MS
    }

    /// Canaries this manager successfully placed (only these are monitored).
    pub fn deployed_canaries(&self) -> Vec<(PathBuf, usize)> {
        self.all_canaries()
            .into_iter()
            .filter(|(path, _)| self.deployed.contains(&platform::path_key(path)))
            .collect()
    }

    fn all_canaries(&self) -> Vec<(PathBuf, usize)> {
        self.dirs
            .iter()
            .flat_map(|dir| {
                CANARY_FILE_NAMES
                    .iter()
                    .enumerate()
                    .map(move |(index, name)| (dir.join(name), index))
            })
            .collect()
    }

    pub fn deploy_all(&mut self) -> usize {
        let dirs = self.dirs.clone();
        dirs.iter().map(|dir| self.deploy_dir(dir)).sum()
    }

    fn deploy_dir(&mut self, dir: &Path) -> usize {
        if !dir.is_dir() {
            return 0;
        }
        let mut placed = 0;
        for (index, name) in CANARY_FILE_NAMES.iter().enumerate() {
            let path = dir.join(name);
            let ok = check_canary(&path, index) == CanaryState::Intact || {
                match self.write_canary(&path, index) {
                    Ok(()) => true,
                    Err(e) => {
                        logger::warn(format!("cannot place canary {}: {e}", path.display()));
                        false
                    }
                }
            };
            if ok {
                platform::set_hidden_file(&path);
                self.deployed.insert(platform::path_key(&path));
                placed += 1;
            }
        }
        placed
    }

    pub fn write_canary(&self, path: &Path, index: usize) -> io::Result<()> {
        self.self_write.store(now_millis(), Ordering::SeqCst);
        if path.exists() {
            let _ = quarantine::set_readonly(path, false);
            // CREATE_ALWAYS fails on hidden files, so replace rather than overwrite.
            fs::remove_file(path)?;
        }
        let result = fs::write(path, canary_content(index));
        if result.is_ok() {
            platform::set_hidden_file(path);
        }
        self.self_write.store(now_millis(), Ordering::SeqCst);
        result
    }

    pub fn set_dirs(&mut self, dirs: Vec<PathBuf>) {
        for dir in dedup_dirs(dirs) {
            let key = platform::path_key(&dir);
            if !self.dirs.iter().any(|d| platform::path_key(d) == key) {
                self.dirs.push(dir.clone());
                let placed = self.deploy_dir(&dir);
                if placed > 0 {
                    logger::info(format!("canaries placed in new folder {}", dir.display()));
                }
            }
        }
    }

    fn resolve(&self, path: &Path) -> Option<(PathBuf, usize)> {
        let key = platform::path_key(path);
        self.deployed_canaries()
            .into_iter()
            .find(|(canary, _)| platform::path_key(canary) == key)
    }

    pub fn handle_fs_event(&mut self, path: &Path) {
        if self.in_cooldown() {
            return;
        }
        let Some((canary, index)) = self.resolve(path) else {
            return;
        };
        let state = check_canary(&canary, index);
        if state != CanaryState::Intact {
            self.on_tamper(&canary, index, state);
        }
    }

    pub fn sweep(&mut self) {
        if self.in_cooldown() {
            return;
        }
        for (canary, index) in self.deployed_canaries() {
            if !canary.parent().is_some_and(Path::is_dir) {
                continue;
            }
            let state = check_canary(&canary, index);
            if state != CanaryState::Intact {
                self.on_tamper(&canary, index, state);
            }
        }
    }

    fn on_tamper(&mut self, canary: &Path, index: usize, state: CanaryState) {
        quarantine::record_event(
            &self.cfg,
            ThreatEvent::new(
                "RANSOMWARE_CANARY",
                Severity::Critical,
                canary.display().to_string(),
                "ALERT_RAISED",
                format!("canary state {state:?}; probable ransomware file encryption or wiping"),
            ),
        );
        match self.write_canary(canary, index) {
            Ok(()) => logger::info(format!("canary recreated: {}", canary.display())),
            Err(e) => {
                self.deployed.remove(&platform::path_key(canary));
                logger::error(format!(
                    "canary recreation failed for {}: {e}",
                    canary.display()
                ));
            }
        }
        self.hunt(canary);
    }

    fn hunt(&mut self, trigger: &Path) {
        if self.last_hunt.is_some_and(|t| t.elapsed() < HUNT_COOLDOWN) {
            return;
        }
        self.last_hunt = Some(Instant::now());

        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, hunt_refresh_kind());
        thread::sleep(HUNT_WINDOW);
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, hunt_refresh_kind());

        let Some(suspect) = select_suspect(&sys) else {
            logger::warn(format!(
                "canary {} tampered but no active non-system writer was found",
                trigger.display()
            ));
            return;
        };
        let action = if self.cfg.dry_run {
            "DRY_RUN: would terminate process".to_string()
        } else if sys.process(suspect.pid).is_some_and(|p| p.kill()) {
            "TERMINATED".to_string()
        } else {
            "TERMINATE_FAILED".to_string()
        };
        let exe = suspect
            .exe
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        quarantine::record_event(
            &self.cfg,
            ThreatEvent::new(
                "RANSOMWARE_SUSPECT",
                Severity::Critical,
                format!("{} (pid {})", suspect.name, suspect.pid.as_u32()),
                action,
                format!(
                    "pid={} name={} exe={} written_bytes_{}ms={} trigger={}",
                    suspect.pid.as_u32(),
                    suspect.name,
                    exe,
                    HUNT_WINDOW.as_millis(),
                    suspect.written_bytes,
                    trigger.display()
                ),
            ),
        );
    }
}

fn hunt_refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_disk_usage()
}

/// Highest active writer in the sampling window, excluding protected and known-safe processes.
pub fn select_suspect(sys: &System) -> Option<WriterSuspect> {
    sys.processes()
        .iter()
        .filter_map(|(pid, process)| {
            let name = OsStr::new(process.name()).to_string_lossy().into_owned();
            let written = process.disk_usage().written_bytes;
            if written <= ACTIVE_WRITE_BYTES
                || platform::is_protected_process(pid.as_u32(), &name)
                || is_safe_writer(&name)
            {
                return None;
            }
            Some(WriterSuspect {
                pid: *pid,
                name,
                exe: process.exe().map(Path::to_path_buf),
                written_bytes: written,
            })
        })
        .max_by_key(|s| s.written_bytes)
}

pub fn run(
    cfg: Arc<AppConfig>,
    dirs: Vec<PathBuf>,
    rx: Receiver<CanaryMsg>,
    shutdown: Arc<AtomicBool>,
) {
    let mut manager = CanaryManager::new(cfg, dirs);
    let placed = manager.deploy_all();
    logger::info(format!(
        "canaries active: {placed} file(s) across {} folder(s)",
        manager.dirs().len()
    ));
    let mut last_sweep = Instant::now();
    while !shutdown.load(Ordering::SeqCst) {
        let message = match rx.recv_timeout(RECV_TIMEOUT) {
            Ok(message) => Some(message),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            match message {
                Some(CanaryMsg::FsEvent(path)) => manager.handle_fs_event(&path),
                Some(CanaryMsg::SetDirs(dirs)) => manager.set_dirs(dirs),
                None => {}
            }
            if last_sweep.elapsed() >= SWEEP_INTERVAL {
                last_sweep = Instant::now();
                manager.sweep();
            }
        }));
        if outcome.is_err() {
            logger::error("canary monitor recovered from a panic");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "thenex-canary-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn content_is_deterministic_and_distinct() {
        assert_eq!(canary_content(0), canary_content(0));
        assert_ne!(canary_content(0), canary_content(1));
        assert!(canary_content(1).starts_with(CANARY_MAGIC));
        assert_eq!(canary_content(1).len(), CANARY_LEN);
    }

    #[test]
    fn canary_names_are_recognized() {
        assert!(is_canary_path(Path::new(r"C:\x\.thenex_canary_01.docx")));
        assert!(is_canary_path(Path::new(".THENEX_CANARY_02.xlsx.locked")));
        assert!(!is_canary_path(Path::new("report.docx")));
    }

    #[test]
    fn deploy_detects_tamper_and_cleans_up() {
        let dir = temp_dir();
        let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("base")));
        let mut manager = CanaryManager::new(cfg, vec![dir.clone()]);
        assert_eq!(manager.deploy_all(), CANARY_FILE_NAMES.len());
        assert!(manager.in_cooldown());

        let (first, index) = manager.deployed_canaries()[0].clone();
        assert_eq!(check_canary(&first, index), CanaryState::Intact);

        let _ = quarantine::set_readonly(&first, false);
        fs::remove_file(&first).unwrap();
        fs::write(&first, b"encrypted!").unwrap();
        assert_eq!(check_canary(&first, index), CanaryState::Modified);
        fs::remove_file(&first).unwrap();
        assert_eq!(check_canary(&first, index), CanaryState::Missing);

        manager.write_canary(&first, index).unwrap();
        assert_eq!(check_canary(&first, index), CanaryState::Intact);

        assert_eq!(remove_canaries(&[dir.clone()]), CANARY_FILE_NAMES.len());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_writers_are_case_insensitive() {
        assert!(is_safe_writer("MsMpEng.exe"));
        assert!(!is_safe_writer("evil.exe"));
    }
}
