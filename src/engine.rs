use crate::bin_ai::{self, BinaryAiScanner};
use crate::canary::{self, CanaryMsg};
use crate::config::AppConfig;
use crate::logger;
use crate::platform;
use crate::process_guard;
use crate::zip_bomb;
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAIN_TICK: Duration = Duration::from_millis(250);
const REDISCOVER_INTERVAL: Duration = Duration::from_secs(60);
const SCAN_SETTLE: Duration = Duration::from_millis(300);
const SCAN_RECV_TIMEOUT: Duration = Duration::from_millis(150);
const MAX_PENDING_SCANS: usize = 50_000;
const BINARY_EXTENSIONS: &[&str] = &["exe", "dll", "scr", "sys", "cpl", "ocx", "com", "efi"];

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
    let read = File::open(path)
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

fn should_ignore(cfg: &AppConfig, path: &Path) -> bool {
    platform::path_is_within(path, &cfg.base_dir) || zip_bomb::is_ignored_extension(path)
}

pub fn scan_path(cfg: &AppConfig, scanner: &BinaryAiScanner, path: &Path) {
    if should_ignore(cfg, path) || !path.is_file() {
        return;
    }
    let kind = classify_file(path);
    if kind == FileKind::Other || !zip_bomb::wait_for_file_ready(path) {
        return;
    }
    match kind {
        FileKind::Archive => {
            zip_bomb::scan_and_respond(path, cfg);
        }
        FileKind::Binary => {
            bin_ai::scan_and_respond(path, cfg, scanner);
        }
        FileKind::Other => {}
    }
}

fn canary_dirs(cfg: &AppConfig) -> Vec<PathBuf> {
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
            let outcome =
                panic::catch_unwind(AssertUnwindSafe(|| scan_path(&cfg, &scanner, &path)));
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
        "The Nex starting (base={}, dry_run={}, model={})",
        cfg.base_dir.display(),
        cfg.dry_run,
        cfg.model_path.display()
    ));

    let cfg = Arc::new(cfg);
    let scanner =
        Arc::new(BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes));
    let (scan_tx, scan_rx) = mpsc::channel::<PathBuf>();
    let (canary_tx, canary_rx) = mpsc::channel::<CanaryMsg>();
    let mut workers = Vec::new();

    {
        let cfg = Arc::clone(&cfg);
        let shutdown = Arc::clone(&shutdown);
        let dirs = canary_dirs(&cfg);
        spawn_worker(&mut workers, "nex-canary", move || {
            canary::run(cfg, dirs, canary_rx, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-file-scan", move || {
            scan_worker(cfg, scanner, scan_rx, shutdown)
        });
    }
    {
        let cfg = Arc::clone(&cfg);
        let scanner = Arc::clone(&scanner);
        let shutdown = Arc::clone(&shutdown);
        spawn_worker(&mut workers, "nex-process-guard", move || {
            process_guard::run(cfg, scanner, shutdown)
        });
    }

    let mut watcher = build_watcher(scan_tx.clone(), canary_tx.clone());
    let mut watched: HashMap<String, PathBuf> = HashMap::new();
    if let Some(w) = watcher.as_mut() {
        refresh_watches(w, &mut watched, &watch_plan(&cfg));
    }
    let mut last_discovery = Instant::now();

    while !shutdown.load(Ordering::SeqCst) {
        thread::sleep(MAIN_TICK);
        if last_discovery.elapsed() < REDISCOVER_INTERVAL {
            continue;
        }
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

    logger::info("The Nex stopping");
    drop(watcher);
    drop(scan_tx);
    drop(canary_tx);
    for worker in workers {
        let _ = worker.join();
    }
    logger::info("The Nex stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn classifies_by_magic_and_extension() {
        let dir = std::env::temp_dir().join(format!("thenex-engine-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
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
    fn data_directory_is_never_scanned() {
        let base = std::env::temp_dir().join("thenex-engine-ignore");
        let cfg = AppConfig::for_base_dir(&base);
        assert!(should_ignore(&cfg, &base.join("Quarantine").join("x.exe")));
        assert!(should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe.crdownload")
        ));
        assert!(!should_ignore(
            &cfg,
            Path::new(r"C:\Users\x\Downloads\a.exe")
        ));
    }
}
