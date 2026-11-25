//! On-demand scans run by the background service. It already runs with the rights (and, on
//! macOS, the Full Disk Access) a scan needs, so the desktop app asks it to scan instead of
//! starting a second privileged process behind a password prompt.
//!
//! A request is an empty file with a fixed name in `<data dir>/requests`, which any local user
//! may create. Only the name is ever looked at, never the content. Any local user can therefore
//! start or cancel a scan. A full scan only reports; a quick scan acts on what it finds in
//! Downloads and Desktop exactly as live protection already does for new files there.
//! shortcut: no per-user authorisation of requests, add it before a scan can do more than that.

use crate::bin_ai::BinaryAiScanner;
use crate::config::AppConfig;
use crate::engine::{self, QuickScanReport, ScanKind, SCAN_PROGRESS_FILE};
use crate::logger;
use crate::schedule;
use crate::status::Telemetry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const REQUEST_DIR_NAME: &str = "requests";
const CANCEL_REQUEST: &str = "cancel-scan";
const PROGRESS_EVERY: Duration = Duration::from_millis(500);
/// Progress older than this was left by a service that stopped mid-scan. Generous: checking one
/// very large program can take a while, and a scan wrongly called dead would show an old result.
const PROGRESS_STALE_SECS: i64 = 120;
pub const BUSY: &str = "A scan is already running";
const POLL_STEP: Duration = Duration::from_millis(200);

fn request_name(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Quick => "quick-scan",
        ScanKind::Full => "full-scan",
        // Never read by `poll`: only the schedule starts one, so nobody can ask for it.
        ScanKind::Scheduled => "scheduled-scan",
    }
}

pub fn request_dir(cfg: &AppConfig) -> PathBuf {
    cfg.base_dir.join(REQUEST_DIR_NAME)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub kind: ScanKind,
    pub running: bool,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub files_examined: u64,
    pub files_scanned: u64,
    pub findings: u64,
    /// Folder being read.
    pub current: String,
}

impl ScanProgress {
    /// Running, and written recently enough that the service is still alive.
    pub fn is_live(&self) -> bool {
        self.running && (Utc::now() - self.updated_at).num_seconds() <= PROGRESS_STALE_SECS
    }
}

fn write_progress(cfg: &AppConfig, progress: &ScanProgress) {
    let path = cfg.log_dir.join(SCAN_PROGRESS_FILE);
    let staging = path.with_extension("json.tmp");
    if let Ok(json) = serde_json::to_vec(progress) {
        if fs::write(&staging, json).is_ok() {
            let _ = fs::rename(&staging, &path);
        }
    }
}

pub fn read_progress(cfg: &AppConfig) -> Option<ScanProgress> {
    serde_json::from_slice(&fs::read(cfg.log_dir.join(SCAN_PROGRESS_FILE)).ok()?).ok()
}

// ---- service side ------------------------------------------------------------------------

/// Creates the request folder: anyone may add a file, nobody but the service may list or
/// remove one. Also clears progress left behind by a previous run.
pub fn prepare(cfg: &AppConfig) -> io::Result<()> {
    let _ = fs::remove_file(cfg.log_dir.join(SCAN_PROGRESS_FILE));
    let dir = request_dir(cfg);
    fs::create_dir_all(&dir)?;
    // Anything left in there (stale requests, or junk a user parked) goes at every start.
    for entry in fs::read_dir(&dir)?.flatten() {
        remove_entry(&entry.path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1733))?;
    }
    Ok(())
}

/// True if the request was there and has been removed. The entry is whatever a local user put
/// under that name, so it is only unlinked (never opened or followed); one that cannot be
/// removed is ignored, or it would start a scan on every poll.
fn take_request(dir: &Path, name: &str) -> bool {
    let path = dir.join(name);
    fs::symlink_metadata(&path).is_ok() && remove_entry(&path)
}

/// Removes whatever a user left at `path` without opening or following it. An immutable flag
/// (`chflags uchg`, which the owner may set) would pin the name and block that request for
/// everyone, so it is cleared and the removal retried.
fn remove_entry(path: &Path) -> bool {
    let remove = || match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path).is_ok(),
        Ok(_) => fs::remove_file(path).is_ok(),
        Err(_) => true,
    };
    if remove() {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
            // SAFETY: `c` is a valid NUL-terminated path; lchflags does not follow a symlink.
            unsafe { libc::lchflags(c.as_ptr(), 0) };
        }
    }
    remove()
}

#[derive(Default)]
pub struct ScanJobs {
    running: AtomicBool,
    cancel: AtomicBool,
}

impl ScanJobs {
    /// Called about once a second by the service: starts a requested scan (one at a time) and
    /// passes on a cancel request.
    pub fn poll(
        self: &Arc<Self>,
        cfg: &Arc<AppConfig>,
        scanner: &Arc<BinaryAiScanner>,
        telemetry: &Arc<Telemetry>,
    ) {
        let dir = request_dir(cfg);
        if take_request(&dir, CANCEL_REQUEST) {
            self.cancel.store(true, Ordering::SeqCst);
        }
        for kind in [ScanKind::Full, ScanKind::Quick] {
            // A request that arrives during a scan is dropped, not queued.
            if take_request(&dir, request_name(kind)) {
                self.start(kind, cfg, scanner, telemetry);
            }
        }
    }

    /// Starts a scan on its own thread unless one is running; true when it was started.
    pub fn start(
        self: &Arc<Self>,
        kind: ScanKind,
        cfg: &Arc<AppConfig>,
        scanner: &Arc<BinaryAiScanner>,
        telemetry: &Arc<Telemetry>,
    ) -> bool {
        if self.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.cancel.store(false, Ordering::SeqCst);
        let (jobs, cfg, scanner, telemetry) = (
            Arc::clone(self),
            Arc::clone(cfg),
            Arc::clone(scanner),
            Arc::clone(telemetry),
        );
        let spawned = thread::Builder::new()
            .name("nex-scan-job".to_string())
            .spawn(move || {
                // Cleared on drop, so a panic in the scan cannot leave the service refusing
                // every later request.
                struct Idle(Arc<ScanJobs>);
                impl Drop for Idle {
                    fn drop(&mut self) {
                        self.0.running.store(false, Ordering::SeqCst);
                    }
                }
                let idle = Idle(jobs);
                if kind == ScanKind::Scheduled {
                    schedule::lower_priority();
                }
                idle.0.run(kind, &cfg, &scanner, &telemetry);
            });
        if let Err(e) = &spawned {
            logger::warn(format!("cannot start the scan: {e}"));
            self.running.store(false, Ordering::SeqCst);
        }
        spawned.is_ok()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stops a running scan at the next folder (service shutdown).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn run(
        &self,
        kind: ScanKind,
        cfg: &AppConfig,
        scanner: &BinaryAiScanner,
        telemetry: &Telemetry,
    ) {
        logger::info(format!("{kind:?} scan requested"));
        let started_at = Utc::now();
        let snapshot = |report: &QuickScanReport, dir: &Path, running: bool| ScanProgress {
            kind,
            running,
            started_at,
            updated_at: Utc::now(),
            files_examined: report.files_examined,
            files_scanned: report.files_scanned,
            findings: report.findings.len() as u64,
            current: dir.display().to_string(),
        };
        let mut last_write: Option<Instant> = None;
        let report = engine::run_scan(cfg, scanner, telemetry, kind, &mut |report, dir| {
            if last_write.is_none_or(|t| t.elapsed() >= PROGRESS_EVERY) {
                last_write = Some(Instant::now());
                write_progress(cfg, &snapshot(report, dir, true));
            }
            !self.cancel.load(Ordering::SeqCst)
        });
        write_progress(cfg, &snapshot(&report, Path::new(""), false));
    }
}

// ---- client side (desktop app) -----------------------------------------------------------

/// True when the service that owns `cfg`'s data folder accepts scan requests.
/// shortcut: Unix only. On Windows the folder inherits an admin-only ACL, so the app keeps its
/// elevation prompt there; grant Users "create files" on it to switch Windows over.
pub fn available(cfg: &AppConfig) -> bool {
    cfg!(unix) && request_dir(cfg).is_dir()
}

fn drop_request(cfg: &AppConfig, name: &str) -> Result<(), String> {
    let path = request_dir(cfg).join(name);
    match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
    {
        Ok(_) => Ok(()),
        // Another user's identical request is already waiting there.
        Err(_) if fs::symlink_metadata(&path).is_ok() => Ok(()),
        Err(e) => Err(format!("could not reach the background service: {e}")),
    }
}

pub fn request(cfg: &AppConfig, kind: ScanKind) -> Result<(), String> {
    if read_progress(cfg).is_some_and(|p| p.is_live()) {
        return Err(BUSY.to_string());
    }
    drop_request(cfg, request_name(kind))
}

pub fn request_cancel(cfg: &AppConfig) -> Result<(), String> {
    drop_request(cfg, CANCEL_REQUEST)
}

/// Asks the service for a scan and waits for its report.
pub fn request_and_wait(
    cfg: &AppConfig,
    kind: ScanKind,
    timeout: Duration,
) -> Result<QuickScanReport, String> {
    let before = engine::read_scan_report(cfg, kind);
    request(cfg, kind)?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        thread::sleep(POLL_STEP);
        match engine::read_scan_report(cfg, kind) {
            Some(report) if Some(&report) != before.as_ref() => return Ok(report),
            _ => {}
        }
    }
    Err("the background service did not answer; check that it is running".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(tag: &str) -> (PathBuf, AppConfig) {
        let root = std::env::temp_dir().join(format!("thenex-jobs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        fs::write(watch.join("notes.txt"), b"plain text").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.watch_dir = Some(watch);
        cfg.ensure_dirs().unwrap();
        prepare(&cfg).unwrap();
        (root, cfg)
    }

    fn service(
        cfg: &AppConfig,
    ) -> (
        Arc<ScanJobs>,
        Arc<AppConfig>,
        Arc<BinaryAiScanner>,
        Arc<Telemetry>,
    ) {
        (
            Arc::new(ScanJobs::default()),
            Arc::new(cfg.clone()),
            Arc::new(BinaryAiScanner::heuristic_only()),
            Arc::new(Telemetry::default()),
        )
    }

    fn wait_idle(jobs: &ScanJobs) {
        for _ in 0..200 {
            if !jobs.running.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("scan job did not finish");
    }

    #[test]
    fn a_requested_full_scan_runs_reports_and_never_moves_files() {
        let (root, cfg) = sandbox("full");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        // The app only hands scans to the service on Unix (see `available`); the service side
        // below is the same on every OS.
        assert_eq!(available(&cfg), cfg!(unix));
        jobs.poll(&shared, &scanner, &telemetry); // nothing requested: nothing happens
        assert!(read_progress(&cfg).is_none());

        request(&cfg, ScanKind::Full).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);

        let report = engine::read_scan_report(&cfg, ScanKind::Full).unwrap();
        assert!(report.full && report.dry_run && !report.cancelled);
        assert_eq!(report.files_examined, 1);
        assert!(!report.finished_at.is_empty());
        let progress = read_progress(&cfg).unwrap();
        assert!(!progress.running && !progress.is_live());
        assert_eq!(progress.files_examined, 1);
        // The request was consumed: polling again does not rescan.
        let first = report.finished_at.clone();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert_eq!(
            engine::read_scan_report(&cfg, ScanKind::Full)
                .unwrap()
                .finished_at,
            first
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_stops_a_scan_and_requests_are_only_names() {
        let (root, cfg) = sandbox("cancel");
        let (jobs, shared, scanner, telemetry) = service(&cfg);
        // A cancel waiting with the request: the cancel is consumed first, the new scan runs whole.
        request_cancel(&cfg).unwrap();
        request(&cfg, ScanKind::Quick).unwrap();
        jobs.poll(&shared, &scanner, &telemetry);
        wait_idle(&jobs);
        assert!(
            !engine::read_scan_report(&cfg, ScanKind::Quick)
                .unwrap()
                .cancelled
        );

        // A cancelled flag set while running stops the walk at the next folder.
        jobs.cancel();
        let report = engine::run_scan(&cfg, &scanner, &telemetry, ScanKind::Full, &mut |_, _| {
            !jobs.cancel.load(Ordering::SeqCst)
        });
        assert!(report.cancelled && report.files_examined == 0);

        // Hostile entries: a directory tree and a dangling symlink under the request name are
        // removed without being followed, and each counts as one request at most.
        let dir = request_dir(&cfg);
        fs::create_dir_all(dir.join("full-scan").join("deep")).unwrap();
        assert!(take_request(&dir, "full-scan"));
        assert!(!take_request(&dir, "full-scan"));
        #[cfg(unix)]
        {
            let outside = root.join("outside.txt");
            fs::write(&outside, b"keep").unwrap();
            std::os::unix::fs::symlink(&outside, dir.join("quick-scan")).unwrap();
            assert!(take_request(&dir, "quick-scan"));
            assert_eq!(fs::read(&outside).unwrap(), b"keep");
        }
        // An immutable request (the owner can set that flag) is still removed, and start-up
        // clears whatever was left in the folder.
        #[cfg(target_os = "macos")]
        {
            let pinned = dir.join("full-scan");
            fs::write(&pinned, b"").unwrap();
            let flagged = std::process::Command::new("/usr/bin/chflags")
                .arg("uchg")
                .arg(&pinned)
                .status();
            if flagged.is_ok_and(|s| s.success()) {
                assert!(fs::remove_file(&pinned).is_err());
                assert!(take_request(&dir, "full-scan"));
            }
        }
        fs::write(dir.join("junk-a-user-left"), b"x").unwrap();
        prepare(&cfg).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_request_during_a_live_scan_is_refused() {
        let (root, cfg) = sandbox("busy");
        write_progress(
            &cfg,
            &ScanProgress {
                kind: ScanKind::Full,
                running: true,
                started_at: Utc::now(),
                updated_at: Utc::now(),
                files_examined: 5,
                files_scanned: 1,
                findings: 0,
                current: "/Applications".to_string(),
            },
        );
        assert!(request(&cfg, ScanKind::Quick).is_err());
        // The same progress, but stale: the service died, so a new request is accepted.
        let mut stale = read_progress(&cfg).unwrap();
        stale.updated_at = Utc::now() - chrono::Duration::seconds(PROGRESS_STALE_SECS + 5);
        write_progress(&cfg, &stale);
        assert!(request(&cfg, ScanKind::Quick).is_ok());
        let _ = fs::remove_dir_all(&root);
    }
}
