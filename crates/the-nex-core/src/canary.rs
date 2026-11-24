use crate::config::{AppConfig, Engine};
use crate::logger;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use crate::status::{CanaryStatus, Telemetry};
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
const PUBLISH_INTERVAL: Duration = Duration::from_secs(5);
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
        // A symlinked canary is tampering: never follow it (we may be root).
        if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return CanaryState::Modified;
        }
        // Bounded read: a ransomware-grown or endless file cannot exhaust memory or stall us.
        let read = quarantine::open_nofollow(path).and_then(|file| {
            let mut data = Vec::new();
            io::Read::read_to_end(&mut io::Read::take(file, CANARY_LEN as u64 + 1), &mut data)
                .map(|_| data)
        });
        match read {
            Ok(data) => {
                return if data == canary_content(index) {
                    CanaryState::Intact
                } else {
                    CanaryState::Modified
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return CanaryState::Missing,
            // A FIFO/device/directory where the canary was: tampering, not a transient error.
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => return CanaryState::Modified,
            Err(_) if attempt + 1 < READ_RETRIES => thread::sleep(READ_RETRY_DELAY),
            Err(_) => return CanaryState::Unreadable,
        }
    }
    CanaryState::Unreadable
}

/// Replaces whatever is at `path` with a fresh canary without ever touching a link target:
/// a symlink is unlinked (not followed) and O_EXCL creation refuses a link planted meanwhile.
pub fn replace_canary(path: &Path, content: &[u8]) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_file() {
                let _ = quarantine::set_readonly(path, false);
            }
            // CREATE_ALWAYS fails on hidden files, so replace rather than overwrite.
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0644: the content is public and deterministic, and the GUI verifies as the user.
        file.set_permissions(fs::Permissions::from_mode(0o644))?; // fchmod on our own handle
    }
    io::Write::write_all(&mut file, content)
}

pub fn remove_canaries(dirs: &[PathBuf]) -> usize {
    let mut removed = 0;
    for dir in dirs {
        for name in CANARY_FILE_NAMES {
            let path = dir.join(name);
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.is_file() {
                    let _ = quarantine::set_readonly(&path, false);
                }
                // remove_file unlinks a symlink itself, never its target.
                if fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

/// A real directory, not a symlink: a user could point Desktop at a folder the root daemon must not write into.
fn is_real_dir(dir: &Path) -> bool {
    fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir())
}

fn dedup_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    dirs.into_iter()
        .filter(|d| seen.insert(platform::path_key(d)))
        .collect()
}

fn status_of(path: PathBuf, state: CanaryState) -> CanaryStatus {
    CanaryStatus {
        path,
        state: format!("{state:?}"),
    }
}

/// Read-only integrity check of every canary slot in `dirs`.
pub fn canary_states(dirs: &[PathBuf]) -> Vec<CanaryStatus> {
    dirs.iter()
        .filter(|dir| is_real_dir(dir))
        .flat_map(|dir| {
            CANARY_FILE_NAMES
                .iter()
                .enumerate()
                .map(move |(index, name)| {
                    let path = dir.join(name);
                    let state = check_canary(&path, index);
                    status_of(path, state)
                })
        })
        .collect()
}

/// Recreates missing or altered canaries (hidden) and reports the resulting state of each.
pub fn rearm_canaries(dirs: &[PathBuf]) -> Vec<CanaryStatus> {
    let mut report = Vec::new();
    for dir in dirs.iter().filter(|dir| is_real_dir(dir)) {
        for (index, name) in CANARY_FILE_NAMES.iter().enumerate() {
            let path = dir.join(name);
            if check_canary(&path, index) != CanaryState::Intact {
                if let Err(e) = replace_canary(&path, &canary_content(index)) {
                    logger::warn(format!("cannot rearm canary {}: {e}", path.display()));
                }
            }
            platform::set_hidden_file(&path);
            let state = check_canary(&path, index);
            report.push(status_of(path, state));
        }
    }
    report
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
        if !is_real_dir(dir) {
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
        let result = replace_canary(path, &canary_content(index));
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
        if !canary.parent().is_some_and(is_real_dir) {
            return;
        }
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
            if !canary.parent().is_some_and(is_real_dir) {
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
        let action = if self.cfg.is_dry_run() {
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

/// Name-based exemption (protected process or known-safe writer) only counts when the image is
/// at an OS-critical path or validly signed, so malware named `svchost.exe` is still a suspect.
/// pid 0/1/4 and ourselves are always exempt; with no readable image path nothing else is (a
/// self-deleting binary must not hide behind a protected name).
fn is_exempt(
    pid: u32,
    name: &str,
    exe: Option<&Path>,
    trusted: impl FnOnce(&Path) -> bool,
) -> bool {
    if matches!(pid, 0 | 1 | 4) || pid == std::process::id() {
        return true;
    }
    if !platform::is_protected_process(pid, name) && !is_safe_writer(name) {
        return false;
    }
    exe.is_some_and(|exe| crate::ai_policy::is_os_critical_path(exe) || trusted(exe))
}

/// Highest active writer in the sampling window, excluding verified protected/safe processes.
pub fn select_suspect(sys: &System) -> Option<WriterSuspect> {
    sys.processes()
        .iter()
        .filter_map(|(pid, process)| {
            let name = OsStr::new(process.name()).to_string_lossy().into_owned();
            let written = process.disk_usage().written_bytes;
            if written <= ACTIVE_WRITE_BYTES
                || is_exempt(
                    pid.as_u32(),
                    &name,
                    process.exe(),
                    platform::is_trusted_binary,
                )
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
    telemetry: Arc<Telemetry>,
    shutdown: Arc<AtomicBool>,
) {
    let enabled = cfg.engine_enabled(Engine::Canary);
    let mut manager = CanaryManager::new(Arc::clone(&cfg), dirs);
    if enabled {
        let placed = manager.deploy_all();
        logger::info(format!(
            "canaries active: {placed} file(s) across {} folder(s)",
            manager.dirs().len()
        ));
    }
    telemetry.set_canaries(canary_states(manager.dirs()));
    let mut was_enabled = enabled;
    let mut last_sweep = Instant::now();
    let mut last_publish = Instant::now();
    while !shutdown.load(Ordering::SeqCst) {
        let message = match rx.recv_timeout(RECV_TIMEOUT) {
            Ok(message) => Some(message),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            let enabled = cfg.engine_enabled(Engine::Canary);
            if enabled && !was_enabled {
                manager.deploy_all();
            }
            was_enabled = enabled;
            let mut changed = false;
            match message {
                Some(CanaryMsg::FsEvent(path)) if enabled => {
                    manager.handle_fs_event(&path);
                    changed = true;
                }
                Some(CanaryMsg::SetDirs(dirs)) => {
                    manager.set_dirs(dirs);
                    changed = true;
                }
                _ => {}
            }
            if enabled && last_sweep.elapsed() >= SWEEP_INTERVAL {
                last_sweep = Instant::now();
                manager.sweep();
                changed = true;
            }
            if changed || last_publish.elapsed() >= PUBLISH_INTERVAL {
                last_publish = Instant::now();
                telemetry.set_canaries(canary_states(manager.dirs()));
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
        assert!(is_canary_path(
            &Path::new("x").join(".thenex_canary_01.docx")
        ));
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

        assert_eq!(
            remove_canaries(std::slice::from_ref(&dir)),
            CANARY_FILE_NAMES.len()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_writers_are_case_insensitive() {
        assert!(is_safe_writer("MsMpEng.exe"));
        assert!(is_safe_writer("mds_stores"));
        assert!(!is_safe_writer("evil.exe"));
    }

    #[test]
    fn name_exemption_needs_a_trusted_image() {
        let spoof = Path::new("/tmp/evil/svchost.exe");
        assert!(!is_exempt(4242, "svchost.exe", Some(spoof), |_| false));
        assert!(!is_exempt(4242, "onedrive.exe", Some(spoof), |_| false));
        assert!(is_exempt(4242, "onedrive.exe", Some(spoof), |_| true)); // validly signed
        assert!(is_exempt(
            4242,
            "mds",
            Some(Path::new("/usr/libexec/mds")),
            |_| false
        ));
        assert!(!is_exempt(4242, "launchd", None, |_| true)); // no image path: name alone never exempts
        assert!(is_exempt(4, "System", None, |_| false));
        assert!(is_exempt(1, "anything", Some(spoof), |_| false));
        assert!(!is_exempt(4242, "evil", Some(spoof), |_| true)); // unlisted name: never exempt
    }

    #[cfg(unix)]
    #[test]
    fn fs_event_ignores_a_folder_swapped_for_a_symlink() {
        let dir = temp_dir();
        let desktop = dir.join("desktop");
        fs::create_dir_all(&desktop).unwrap();
        let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("base")));
        let mut manager = CanaryManager::new(cfg, vec![desktop.clone()]);
        assert_eq!(manager.deploy_all(), CANARY_FILE_NAMES.len());
        let (canary, _) = manager.deployed_canaries()[0].clone();

        // Desktop is swapped for a link to a folder root must never write into.
        let victim = dir.join("victim");
        fs::create_dir_all(&victim).unwrap();
        let moved = dir.join("desktop-real");
        fs::rename(&desktop, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &desktop).unwrap();
        manager.self_write.store(0, Ordering::SeqCst);
        manager.handle_fs_event(&canary);
        assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rearm_restores_and_reports_every_slot() {
        let dir = temp_dir();
        let states = canary_states(std::slice::from_ref(&dir));
        assert_eq!(states.len(), CANARY_FILE_NAMES.len());
        assert!(states.iter().all(|s| s.state == "Missing"));

        let report = rearm_canaries(std::slice::from_ref(&dir));
        assert!(report.iter().all(CanaryStatus::is_intact), "{report:?}");

        let tampered = dir.join(CANARY_FILE_NAMES[1]);
        let _ = fs::remove_file(&tampered);
        fs::write(&tampered, b"ransom note").unwrap();
        let states = canary_states(std::slice::from_ref(&dir));
        assert_eq!(states[1].state, "Modified");
        assert!(rearm_canaries(std::slice::from_ref(&dir))
            .iter()
            .all(CanaryStatus::is_intact));
        assert!(canary_states(&[dir.join("missing-folder")]).is_empty());

        remove_canaries(std::slice::from_ref(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
