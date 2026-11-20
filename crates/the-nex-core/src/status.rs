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
    pub watched_dirs: Vec<PathBuf>,
    pub canaries: Vec<CanaryStatus>,
    pub quarantine: Vec<QuarantineMeta>,
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
        watched_dirs: telemetry.watched_dirs(),
        canaries: telemetry.canaries(),
        quarantine: quarantine::list_quarantined(cfg).unwrap_or_default(),
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
}
