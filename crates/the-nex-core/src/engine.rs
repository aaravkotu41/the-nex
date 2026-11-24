use crate::bin_ai::{self, BinaryAiScanner};
use crate::canary::{self, CanaryMsg};
use crate::config::{AppConfig, Engine};
use crate::logger;
use crate::platform;
use crate::process_guard;
use crate::quarantine::{self, Severity, ThreatEvent};
use crate::status::{self, ResourceUsage, Telemetry};
use crate::zip_bomb;
use chrono::Utc;
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const MAIN_TICK: Duration = Duration::from_millis(250);
const SETTINGS_RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_INTERVAL: Duration = Duration::from_secs(2);
const REDISCOVER_INTERVAL: Duration = Duration::from_secs(60);
const SCAN_SETTLE: Duration = Duration::from_millis(300);
const SCAN_RECV_TIMEOUT: Duration = Duration::from_millis(150);
const MAX_PENDING_SCANS: usize = 50_000;
const QUICK_SCAN_MAX_DEPTH: usize = 8;
const QUICK_SCAN_MAX_FILES: u64 = 50_000;
const BINARY_EXTENSIONS: &[&str] = &["exe", "dll", "scr", "sys", "cpl", "ocx", "com", "efi"];
/// Written next to events.jsonl by `--quick-scan` so callers that cannot read stdout (UAC) get the report.
pub const QUICK_SCAN_REPORT_FILE: &str = "last_quick_scan.json";

/// Thin (32/64-bit, either byte order) and fat/universal Mach-O headers.
#[cfg(target_os = "macos")]
fn is_macho_magic(magic: &[u8; 4]) -> bool {
    matches!(
        magic,
        [0xCF, 0xFA, 0xED, 0xFE]
            | [0xCE, 0xFA, 0xED, 0xFE]
            | [0xFE, 0xED, 0xFA, 0xCF]
            | [0xFE, 0xED, 0xFA, 0xCE]
            | [0xCA, 0xFE, 0xBA, 0xBE]
            | [0xCA, 0xFE, 0xBA, 0xBF]
    )
}

#[cfg(not(target_os = "macos"))]
fn is_macho_magic(_magic: &[u8; 4]) -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Archive,
    Binary,
    Other,
}

/// Cheap triage by magic bytes (and extension for files still being written).
pub fn classify_file(path: &Path) -> FileKind {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut magic = [0u8; 4];
    // No-follow, non-blocking: a FIFO or symlink swapped in after the lstat must not hang the scan.
    let read = quarantine::open_nofollow(path)
        .and_then(|mut f| f.read(&mut magic))
        .unwrap_or(0);
    if (read >= 2 && &magic[..2] == b"MZ") || (read == 4 && is_macho_magic(&magic)) {
        return FileKind::Binary;
    }
    if (read == 4 && (&magic == b"PK\x03\x04" || &magic == b"PK\x05\x06")) || ext == "zip" {
        return FileKind::Archive;
    }
    if BINARY_EXTENSIONS.contains(&ext.as_str()) {
        return FileKind::Binary;
    }
    FileKind::Other
}

/// The Nex's own data, quarantine and log folders are never scanned.
fn should_ignore(cfg: &AppConfig, path: &Path) -> bool {
    platform::path_is_within(path, &cfg.base_dir)
        || platform::path_is_within(path, &cfg.quarantine_dir)
        || is_engine_output(cfg, path)
        || zip_bomb::is_ignored_extension(path)
}

/// The files the engine itself writes next to the event log (including rotated and
/// staging copies). Only these are skipped, not the whole folder: `--log-file` may
/// point into a watched directory, which must stay protected.
fn is_engine_output(cfg: &AppConfig, path: &Path) -> bool {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let same_dir = platform::path_is_within(parent, &cfg.log_dir)
        && platform::path_is_within(&cfg.log_dir, parent);
    if !same_dir {
        return false;
    }
    let name = name.to_string_lossy().to_lowercase();
    let events = cfg
        .events_log
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let own_files = [
        events.as_str(),
        crate::config::STATUS_FILE_NAME,
        QUICK_SCAN_REPORT_FILE,
        logger::LOG_FILE_NAME,
    ];
    let is_own = own_files
        .iter()
        .any(|own| !own.is_empty() && name.starts_with(&own.to_lowercase()));
    is_own
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuickScanFinding {
    pub path: PathBuf,
    pub threat_type: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QuickScanReport {
    pub roots: Vec<PathBuf>,
    pub files_examined: u64,
    pub files_scanned: u64,
    pub findings: Vec<QuickScanFinding>,
    pub dry_run: bool,
    pub truncated: bool,
    pub duration_ms: u64,
}

/// Inspects one complete file with the enabled engines; detections are acted on and logged.
fn inspect_file(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    path: &Path,
    kind: FileKind,
    telemetry: &Telemetry,
) -> Option<QuickScanFinding> {
    match kind {
        FileKind::Archive if cfg.engine_enabled(Engine::ZipBomb) => {
            telemetry.add_files_scanned(1);
            zip_bomb::scan_and_respond(path, cfg).map(|threat| QuickScanFinding {
                path: path.to_path_buf(),
                threat_type: "ZIP_BOMB".to_string(),
                detail: threat.summary(),
            })
        }
        FileKind::Binary if cfg.engine_enabled(Engine::BinAi) => {
            telemetry.add_files_scanned(1);
            bin_ai::scan_and_respond(path, cfg, scanner)
                .and_then(|outcome| outcome.detection)
                .map(|detail| QuickScanFinding {
                    path: path.to_path_buf(),
                    threat_type: "MALWARE_AI".to_string(),
                    detail,
                })
        }
        _ => None,
    }
}

/// True only for a regular file; symlinks are never followed into scanning or quarantine
/// (a link could point at a file the daemon's privileges can touch but the writer cannot).
pub fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Live path: waits for the writer to finish, then inspects.
pub fn scan_path(cfg: &AppConfig, scanner: &BinaryAiScanner, path: &Path, telemetry: &Telemetry) {
    if should_ignore(cfg, path) || !is_regular_file(path) {
        return;
    }
    let kind = classify_file(path);
    if kind == FileKind::Other || !zip_bomb::wait_for_file_ready(path) {
        return;
    }
    inspect_file(cfg, scanner, path, kind, telemetry);
}

/// One-shot recursive scan of existing files under `roots` (bounded in depth and file count).
pub fn quick_scan(
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
    roots: &[PathBuf],
    telemetry: &Telemetry,
) -> QuickScanReport {
    let started = Instant::now();
    let mut report = QuickScanReport {
        roots: roots.to_vec(),
        dry_run: cfg.is_dry_run(),
        ..QuickScanReport::default()
    };
    let scanned_before = telemetry.files_scanned.load(Ordering::Relaxed);
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() || should_ignore(cfg, &path) {
                continue;
            }
            if kind.is_dir() {
                if depth < QUICK_SCAN_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            report.files_examined += 1;
            if report.files_examined > QUICK_SCAN_MAX_FILES {
                report.truncated = true;
                break 'walk;
            }
            let file_kind = classify_file(&path);
            if file_kind == FileKind::Other {
                continue;
            }
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                inspect_file(cfg, scanner, &path, file_kind, telemetry)
            }));
            if let Ok(Some(finding)) = outcome {
                report.findings.push(finding);
            }
        }
    }
    report.files_scanned = telemetry.files_scanned.load(Ordering::Relaxed) - scanned_before;
    report.duration_ms = started.elapsed().as_millis() as u64;
    report
}

/// Full quick scan as run by `--quick-scan` and the desktop app: scan, log a QUICK_SCAN summary
/// event and leave the report next to events.jsonl.
pub fn run_quick_scan(cfg: &AppConfig, scanner: &BinaryAiScanner) -> QuickScanReport {
    let roots = quick_scan_roots(cfg);
    let report = quick_scan(cfg, scanner, &roots, &Telemetry::default());
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "QUICK_SCAN",
            if report.findings.is_empty() {
                Severity::Low
            } else {
                Severity::High
            },
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join("; "),
            format!("{} threat(s) found", report.findings.len()),
            format!(
                "examined={} scanned={} truncated={} duration_ms={}",
                report.files_examined, report.files_scanned, report.truncated, report.duration_ms
            ),
        ),
    );
    if let Ok(json) = serde_json::to_vec_pretty(&report) {
        let _ = fs::write(cfg.log_dir.join(QUICK_SCAN_REPORT_FILE), json);
    }
    report
}

pub fn read_last_quick_scan(cfg: &AppConfig) -> Option<QuickScanReport> {
    serde_json::from_slice(&fs::read(cfg.log_dir.join(QUICK_SCAN_REPORT_FILE)).ok()?).ok()
}

pub fn quick_scan_roots(cfg: &AppConfig) -> Vec<PathBuf> {
    match &cfg.watch_dir {
        Some(dir) => vec![dir.clone()],
        None => platform::discover_quick_scan_dirs(),
    }
}

pub fn canary_dirs(cfg: &AppConfig) -> Vec<PathBuf> {
    match &cfg.watch_dir {
        Some(dir) => vec![dir.clone()],
        None => platform::discover_canary_dirs(),
    }
}

/// (directory, recursive). Canary-only folders are watched top-level only.
fn watch_plan(cfg: &AppConfig) -> Vec<(PathBuf, bool)> {
    if let Some(dir) = &cfg.watch_dir {
        return vec![(dir.clone(), true)];
    }
    let mut plan: Vec<(PathBuf, bool)> = platform::discover_watched_dirs()
        .into_iter()
        .map(|dir| (dir, true))
        .collect();
    for dir in platform::discover_canary_dirs() {
        let covered = plan.iter().any(|(watched, recursive)| {
            platform::path_key(watched) == platform::path_key(&dir)
                || (*recursive && platform::path_is_within(&dir, watched))
        });
        if !covered {
            plan.push((dir, false));
        }
    }
    plan
}

fn dispatch_event(event: Event, scan_tx: &Sender<PathBuf>, canary_tx: &Sender<CanaryMsg>) {
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }
    let scan_relevant = matches!(
        event.kind,
        EventKind::Any
            | EventKind::Create(_)
            | EventKind::Modify(
                ModifyKind::Any | ModifyKind::Data(_) | ModifyKind::Name(_) | ModifyKind::Other
            )
    );
    for path in event.paths {
        if canary::is_canary_path(&path) {
            let _ = canary_tx.send(CanaryMsg::FsEvent(path));
        } else if scan_relevant {
            let _ = scan_tx.send(path);
        }
    }
}

fn build_watcher(
    scan_tx: Sender<PathBuf>,
    canary_tx: Sender<CanaryMsg>,
) -> Option<RecommendedWatcher> {
    let handler = move |result: notify::Result<Event>| match result {
        Ok(event) => dispatch_event(event, &scan_tx, &canary_tx),
        Err(e) => logger::warn(format!("file watcher error: {e}")),
    };
    match notify::recommended_watcher(handler) {
        Ok(watcher) => Some(watcher),
        Err(e) => {
            logger::error(format!("cannot create file watcher: {e}"));
            None
        }
    }
}

fn refresh_watches(
    watcher: &mut RecommendedWatcher,
    watched: &mut HashMap<String, PathBuf>,
    plan: &[(PathBuf, bool)],
) {
    watched.retain(|_, dir| {
        if dir.is_dir() {
            true
        } else {
            let _ = watcher.unwatch(dir);
            false
        }
    });
    for (dir, recursive) in plan {
        let key = platform::path_key(dir);
        if watched.contains_key(&key) || !dir.is_dir() {
            continue;
        }
        let mode = if *recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        match watcher.watch(dir, mode) {
            Ok(()) => {
                logger::info(format!(
                    "watching {} ({})",
                    dir.display(),
                    if *recursive { "recursive" } else { "top level" }
                ));
                watched.insert(key, dir.clone());
            }
            Err(e) => logger::warn(format!("cannot watch {}: {e}", dir.display())),
        }
    }
}

fn scan_worker(
    cfg: Arc<AppConfig>,
    scanner: Arc<BinaryAiScanner>,
    telemetry: Arc<Telemetry>,
    rx: Receiver<PathBuf>,
    shutdown: Arc<AtomicBool>,
) {
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    while !shutdown.load(Ordering::SeqCst) {
        match rx.recv_timeout(SCAN_RECV_TIMEOUT) {
            Ok(path) => {
                pending.insert(path, Instant::now());
                while let Ok(more) = rx.try_recv() {
                    pending.insert(more, Instant::now());
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if pending.len() > MAX_PENDING_SCANS {
            logger::warn(format!(
                "file event backlog exceeded {MAX_PENDING_SCANS}; dropping queued scans"
            ));
            pending.clear();
        }
        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, seen)| seen.elapsed() >= SCAN_SETTLE)
            .map(|(path, _)| path.clone())
            .collect();
        for path in ready {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            pending.remove(&path);
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                scan_path(&cfg, &scanner, &path, &telemetry)
            }));
            if outcome.is_err() {
                logger::error(format!(
                    "file scanner recovered from a panic on {}",
                    path.display()
                ));
            }
        }
    }
}

fn spawn_worker<F>(workers: &mut Vec<JoinHandle<()>>, name: &str, body: F)
where
    F: FnOnce() + Send + 'static,
{
    match thread::Builder::new().name(name.to_string()).spawn(body) {
        Ok(handle) => workers.push(handle),
        Err(e) => logger::error(format!("cannot start {name}: {e}")),
    }
}

/// Runs every detector until `shutdown` is set. Used by both the service and `--console`.
pub fn run(cfg: AppConfig, shutdown: Arc<AtomicBool>) {
    logger::init(&cfg.log_dir, cfg.interactive);
    panic::set_hook(Box::new(|info| logger::error(format!("panic: {info}"))));
    if let Err(e) = cfg.ensure_dirs() {
        logger::error(format!("startup: {e}"));
    }
    logger::info(format!(
        "The Nex starting (base={}, events={}, quarantine={}, dry_run={}, model={})",
        cfg.base_dir.display(),
        cfg.events_log.display(),
        cfg.quarantine_dir.display(),
        cfg.is_dry_run(),
        cfg.model_path.display()
    ));

    let started_at = Utc::now();
    let cfg = Arc::new(cfg);
    let telemetry = Arc::new(Telemetry::default());
    let scanner =
        Arc::new(BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes));
    telemetry
        .model_loaded
        .store(scanner.has_model(), Ordering::Relaxed);
    let (scan_tx, scan_rx) = mpsc::channel::<PathBuf>();
    let (canary_tx, canary_rx) = mpsc::channel::<CanaryMsg>();
    let mut workers = Vec::new();

    {
        let cfg = Arc::clone(&cfg);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        let dirs = canary_dirs(&cfg);
        spawn_worker(&mut workers, "nex-canary", move || {
            canary::run(cfg, dirs, canary_rx, telemetry, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-file-scan", move || {
            scan_worker(cfg, scanner, telemetry, scan_rx, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let telemetry = Arc::clone(&telemetry);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-process-guard", move || {
            process_guard::run(cfg, scanner, telemetry, shutdown)
        });
    }

    let mut watcher = build_watcher(scan_tx.clone(), canary_tx.clone());
    let mut watched: HashMap<String, PathBuf> = HashMap::new();
    if let Some(w) = watcher.as_mut() {
        refresh_watches(w, &mut watched, &watch_plan(&cfg));
    }
    let mut last_discovery = Instant::now();
    let mut last_settings = Instant::now();
    let mut last_status: Option<Instant> = None;
    let mut status_error_logged = false;
    let mut own_process = System::new();
    let own_pid = Pid::from_u32(std::process::id());
    let cpu_count = thread::available_parallelism()
        .map(|n| n.get() as f32)
        .unwrap_or(1.0);

    while !shutdown.load(Ordering::SeqCst) {
        if last_settings.elapsed() >= SETTINGS_RELOAD_INTERVAL {
            last_settings = Instant::now();
            if let Some(toggles) = cfg.toggles.reload_if_changed(&cfg.settings_file) {
                logger::info(format!("settings reloaded: {toggles:?}"));
            }
        }
        if last_status.is_none_or(|t| t.elapsed() >= STATUS_INTERVAL) {
            last_status = Some(Instant::now());
            telemetry.set_watched_dirs(watched.values().cloned().collect());
            own_process.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[own_pid]),
                true,
                ProcessRefreshKind::nothing().with_memory().with_cpu(),
            );
            let usage = own_process
                .process(own_pid)
                .map(|p| ResourceUsage {
                    memory_bytes: p.memory(),
                    cpu_percent: p.cpu_usage() / cpu_count,
                })
                .unwrap_or_default();
            let snapshot = status::build_status(&cfg, &telemetry, started_at, usage);
            match status::write_status(&cfg.status_file, &snapshot) {
                Ok(()) => status_error_logged = false,
                Err(e) if !status_error_logged => {
                    status_error_logged = true;
                    logger::warn(format!("cannot write {}: {e}", cfg.status_file.display()));
                }
                Err(_) => {}
            }
        }
        if last_discovery.elapsed() >= REDISCOVER_INTERVAL {
            last_discovery = Instant::now();
            if watcher.is_none() {
                watcher = build_watcher(scan_tx.clone(), canary_tx.clone());
                watched.clear();
            }
            if let Some(w) = watcher.as_mut() {
                refresh_watches(w, &mut watched, &watch_plan(&cfg));
            }
            if cfg.watch_dir.is_none() {
                let _ = canary_tx.send(CanaryMsg::SetDirs(platform::discover_canary_dirs()));
            }
        }
        thread::sleep(MAIN_TICK);
    }

    logger::info("The Nex stopping");
    drop(watcher);
    drop(scan_tx);
    drop(canary_tx);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = fs::remove_file(&cfg.status_file);
    logger::info("The Nex stopped");
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_regular_files() {
        let dir = std::env::temp_dir().join(format!("thenex-sym-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let real = dir.join("real");
        fs::write(&real, b"x").unwrap();
        let link = dir.join("link");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(super::is_regular_file(&real));
        assert!(!super::is_regular_file(&link));
        let _ = fs::remove_dir_all(&dir);
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn classify_file_does_not_hang_on_a_fifo_or_follow_a_link() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("thenex-fifo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe.dat");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(classify_file(&fifo), FileKind::Other); // returns instead of blocking

        let real = dir.join("real.dat");
        fs::write(&real, b"MZ\x90\x00").unwrap();
        let link = dir.join("link.dat");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(classify_file(&real), FileKind::Binary);
        assert_eq!(classify_file(&link), FileKind::Other);
        let _ = fs::remove_dir_all(&dir);
    }

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-engine-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn classifies_by_magic_and_extension() {
        let dir = temp_root("classify");
        let cases = [
            ("a.bin", b"MZ\x90\x00rest".to_vec(), FileKind::Binary),
            ("b.dat", b"PK\x03\x04rest".to_vec(), FileKind::Archive),
            ("c.zip", b"garbage".to_vec(), FileKind::Archive),
            ("d.exe", Vec::new(), FileKind::Binary),
            ("e.txt", b"hello".to_vec(), FileKind::Other),
        ];
        for (name, bytes, expected) in cases {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            assert_eq!(classify_file(&path), expected, "{name}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_directories_are_never_scanned() {
        let base = std::env::temp_dir().join("thenex-engine-ignore");
        let quarantine = base.join("q-elsewhere");
        let events = base.join("l").join("e.jsonl");
        let cfg = AppConfig::for_base_dir(&base)
            .with_overrides(Some(quarantine.as_path()), Some(events.as_path()));
        assert!(should_ignore(&cfg, &base.join("Quarantine").join("x.exe")));
        assert!(should_ignore(&cfg, &base.join("q-elsewhere").join("x.exe")));
        assert!(should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe.crdownload")
        ));
        assert!(!should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe")
        ));
    }

    /// `--log-file` inside a watched folder must not blind the scanner to that folder.
    #[test]
    fn log_file_beside_watched_files_only_skips_engine_output() {
        let root = std::env::temp_dir().join("thenex-engine-logbeside");
        let watch = root.join("watch");
        let cfg = AppConfig::for_base_dir(&root.join("base")).with_overrides(
            Some(root.join("quarantine").as_path()),
            Some(root.join("events.jsonl").as_path()),
        );
        for own in [
            "events.jsonl",
            "events.jsonl.1",
            "status.json",
            "status.json.tmp",
            "last_quick_scan.json",
            "thenex.log",
            "thenex.log.1",
        ] {
            assert!(should_ignore(&cfg, &root.join(own)), "{own}");
        }
        assert!(!should_ignore(&cfg, &root.join("invoice.zip")));
        assert!(!should_ignore(&cfg, &watch.join("ratio_bomb.zip")));
        assert!(!should_ignore(&cfg, &watch.join("events.jsonl")));
    }

    #[test]
    fn quick_scan_walks_and_respects_toggles() {
        let root = temp_root("quick");
        let watch = root.join("watch");
        fs::create_dir_all(watch.join("nested")).unwrap();
        fs::write(watch.join("notes.txt"), b"plain text").unwrap();
        fs::write(watch.join("nested").join("broken.zip"), b"not really a zip").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.dry_run = true;
        cfg.watch_dir = Some(watch.clone());
        let scanner = BinaryAiScanner::heuristic_only();
        let telemetry = Telemetry::default();

        let report = quick_scan(&cfg, &scanner, &quick_scan_roots(&cfg), &telemetry);
        assert_eq!(report.roots, vec![watch.clone()]);
        assert_eq!(report.files_examined, 2);
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        assert!(report.dry_run);

        let mut toggles = cfg.toggles.snapshot();
        toggles.set(Engine::ZipBomb, false);
        cfg.toggles.apply(toggles);
        let report = quick_scan(&cfg, &scanner, &[watch], &telemetry);
        assert_eq!(report.files_scanned, 0);
        let _ = fs::remove_dir_all(&root);
    }
}
