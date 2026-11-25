use crate::config::{AppConfig, RuntimeToggles};
use crate::logger::lock_or_recover;
use crate::quarantine::{self, QuarantineMeta};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A status.json older than this means the daemon is not running.
pub const STALE_AFTER_SECS: i64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryStatus {
    pub path: PathBuf,
    pub state: String,
}

impl CanaryStatus {
    pub fn is_intact(&self) -> bool {
        self.state == "Intact"
    }
}

/// Counters shared by the detector threads and published to status.json.
#[derive(Debug, Default)]
pub struct Telemetry {
    pub files_scanned: AtomicU64,
    pub processes_inspected: AtomicU64,
    pub processes_watched: AtomicU64,
    pub model_loaded: AtomicBool,
    canaries: Mutex<Vec<CanaryStatus>>,
    watched_dirs: Mutex<Vec<PathBuf>>,
    full_disk_access: Mutex<Option<(Instant, Option<bool>)>>,
}

/// A file only a process with Full Disk Access may open (macOS keeps the system privacy
/// database behind it). Opening it asks nothing of the user: macOS just refuses.
#[cfg(target_os = "macos")]
const FDA_PROBE_FILE: &str = "/Library/Application Support/com.apple.TCC/TCC.db";
/// Cheap, but a refused open is logged by the OS, so it is not repeated on every status write.
const FDA_RECHECK: Duration = Duration::from_secs(6);

/// Some(true) when `path` opens, Some(false) when the OS refuses it, None when it cannot say
/// (missing file, any other error). The file is closed at once and never read.
pub fn probe_open(path: &Path) -> Option<bool> {
    match fs::File::open(path) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Some(false),
        Err(_) => None,
    }
}

impl Telemetry {
    pub fn add_files_scanned(&self, n: u64) {
        self.files_scanned.fetch_add(n, Ordering::Relaxed);
    }

    pub fn set_canaries(&self, canaries: Vec<CanaryStatus>) {
        *lock_or_recover(&self.canaries) = canaries;
    }

    pub fn canaries(&self) -> Vec<CanaryStatus> {
        lock_or_recover(&self.canaries).clone()
    }

    /// Whether this process has macOS Full Disk Access: None elsewhere and when unknown.
    pub fn full_disk_access(&self) -> Option<bool> {
        #[cfg(target_os = "macos")]
        {
            let mut last = lock_or_recover(&self.full_disk_access);
            if let Some((at, value)) = *last {
                if at.elapsed() < FDA_RECHECK {
                    return value;
                }
            }
            let value = probe_open(Path::new(FDA_PROBE_FILE));
            *last = Some((Instant::now(), value));
            value
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (&self.full_disk_access, FDA_RECHECK);
            None
        }
    }

    pub fn set_watched_dirs(&self, dirs: Vec<PathBuf>) {
        *lock_or_recover(&self.watched_dirs) = dirs;
    }

    pub fn watched_dirs(&self) -> Vec<PathBuf> {
        lock_or_recover(&self.watched_dirs).clone()
    }
}

/// The daemon's own footprint, measured by itself (standard users cannot query a SYSTEM process).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_percent: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineStatus {
    pub version: String,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub heartbeat: DateTime<Utc>,
    #[serde(default)]
    pub usage: ResourceUsage,
    pub dry_run: bool,
    pub toggles: RuntimeToggles,
    pub files_scanned: u64,
    pub processes_inspected: u64,
    pub processes_watched: u64,
    pub threats_detected: u64,
    pub model_loaded: bool,
    pub model_path: PathBuf,
    /// Entries in the loaded known-malware list (0 = none installed) and when it was built.
    #[serde(default)]
    pub known_bad_entries: u64,
    #[serde(default)]
    pub known_bad_created: Option<DateTime<Utc>>,
    pub watched_dirs: Vec<PathBuf>,
    pub canaries: Vec<CanaryStatus>,
    pub quarantine: Vec<QuarantineMeta>,
    /// macOS only: whether the service itself can read protected folders. The app cannot see
    /// this, so the service says it. None = unknown, not applicable, or an older service.
    #[serde(default)]
    pub full_disk_access: Option<bool>,
}

impl EngineStatus {
    pub fn is_fresh(&self) -> bool {
        (Utc::now() - self.heartbeat).num_seconds() <= STALE_AFTER_SECS
    }

    pub fn scanned(&self) -> u64 {
        self.files_scanned + self.processes_inspected
    }
}

pub fn build_status(
    cfg: &AppConfig,
    telemetry: &Telemetry,
    started_at: DateTime<Utc>,
    usage: ResourceUsage,
) -> EngineStatus {
    EngineStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        started_at,
        heartbeat: Utc::now(),
        usage,
        dry_run: cfg.is_dry_run(),
        toggles: cfg.toggles.snapshot(),
        files_scanned: telemetry.files_scanned.load(Ordering::Relaxed),
        processes_inspected: telemetry.processes_inspected.load(Ordering::Relaxed),
        processes_watched: telemetry.processes_watched.load(Ordering::Relaxed),
        threats_detected: quarantine::threat_events_recorded(),
        model_loaded: telemetry.model_loaded.load(Ordering::Relaxed),
        model_path: cfg.model_path.clone(),
        known_bad_entries: cfg.known_bad.len() as u64,
        known_bad_created: cfg.known_bad.created(),
        watched_dirs: telemetry.watched_dirs(),
        canaries: telemetry.canaries(),
        quarantine: quarantine::list_quarantined(cfg).unwrap_or_default(),
        full_disk_access: telemetry.full_disk_access(),
    }
}

pub fn write_status(path: &Path, status: &EngineStatus) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = path.with_extension("json.tmp");
    fs::write(
        &staging,
        serde_json::to_vec(status).map_err(io::Error::other)?,
    )?;
    fs::rename(&staging, path)
}

pub fn read_status(path: &Path) -> Option<EngineStatus> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_and_ages() {
        let dir = std::env::temp_dir().join(format!("thenex-status-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = AppConfig::for_base_dir(&dir);
        let telemetry = Telemetry::default();
        telemetry.add_files_scanned(3);
        telemetry.processes_inspected.store(4, Ordering::Relaxed);
        telemetry.set_canaries(vec![CanaryStatus {
            path: dir.join(".thenex_canary_01.docx"),
            state: "Intact".into(),
        }]);
        let usage = ResourceUsage {
            memory_bytes: 14 * 1024 * 1024,
            cpu_percent: 0.2,
        };
        let mut status = build_status(&cfg, &telemetry, Utc::now(), usage);
        assert_eq!(status.usage, usage);
        assert_eq!(status.scanned(), 7);
        assert!(status.is_fresh());
        write_status(&cfg.status_file, &status).unwrap();
        assert_eq!(read_status(&cfg.status_file), Some(status.clone()));

        status.heartbeat = Utc::now() - chrono::Duration::seconds(STALE_AFTER_SECS + 5);
        assert!(!status.is_fresh());
        assert!(status.canaries[0].is_intact());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_disk_access_is_optional_in_both_directions() {
        let cfg = AppConfig::for_base_dir(&std::env::temp_dir().join("thenex-status-fda"));
        let status = build_status(
            &cfg,
            &Telemetry::default(),
            Utc::now(),
            ResourceUsage::default(),
        );
        let mut json = serde_json::to_value(&status).unwrap();
        // A status written by an older service has no such field.
        json.as_object_mut().unwrap().remove("full_disk_access");
        let old: EngineStatus = serde_json::from_value(json).unwrap();
        assert_eq!(old.full_disk_access, None);
        for value in [Some(true), Some(false), None] {
            let mut next = status.clone();
            next.full_disk_access = value;
            let text = serde_json::to_string(&next).unwrap();
            assert_eq!(serde_json::from_str::<EngineStatus>(&text).unwrap(), next);
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(status.full_disk_access, None);
    }

    #[test]
    fn the_probe_tells_denied_from_missing_and_never_reads() {
        let dir = std::env::temp_dir().join(format!("thenex-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("protected");
        fs::write(&file, b"secret").unwrap();
        assert_eq!(probe_open(&file), Some(true));
        assert_eq!(probe_open(&dir.join("missing")), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0)).unwrap();
            // Root can open anything, which would make this check meaningless.
            if fs::File::open(&file).is_err() {
                assert_eq!(probe_open(&file), Some(false));
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
