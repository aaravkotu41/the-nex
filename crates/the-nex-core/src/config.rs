use crate::allowlist::{self, LiveAllowed};
use crate::known_bad::{self, Digest32, KnownBad};
use crate::schedule::{self, ScanSchedule};
use crate::skiplist::{self, LiveSkipped};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

pub const MAX_ZIP_RATIO: f64 = 100.0;
pub const MAX_UNCOMPRESSED_BYTES: u64 = 5 * 1024 * 1024 * 1024;
pub const MAX_ZIP_DEPTH: u32 = 3;
pub const MAX_NESTED_MEM_READ: u64 = 16 * 1024 * 1024;
pub const AI_MALWARE_THRESHOLD: f32 = 0.65;
/// Ratio alone is not dangerous below this much expanded content.
pub const MIN_RATIO_CHECK_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_AI_SCAN_BYTES: u64 = 100 * 1024 * 1024;

pub const SERVICE_NAME: &str = "TheNex";
pub const MODEL_FILE_NAME: &str = "thenex_model.onnx";
pub const QUARANTINE_DIR_NAME: &str = "Quarantine";
pub const LOG_DIR_NAME: &str = "logs";
pub const EVENTS_FILE_NAME: &str = "events.jsonl";
pub const SETTINGS_FILE_NAME: &str = "settings.json";
pub const STATUS_FILE_NAME: &str = "status.json";
/// Overrides the data directory (tests, development).
pub const DATA_DIR_ENV: &str = "THENEX_DATA_DIR";

pub const USAGE: &str = "\
Usage: the-nex [MODE] [OPTIONS]

Modes:
  (no arguments)            run as the native background service / LaunchDaemon
  --install                 register the service, notifier and tray autostart (Administrator)
  --uninstall               remove the service, autostart entries and canaries (Administrator)
  --console                 run the protection engine in this console
  --notifier                show desktop notifications for new threat events
  --tray                    show the system tray icon (Windows)
  --quick-scan              scan Downloads and Desktop (or --watch-dir) once and exit
  --full-scan               scan the whole disk (or --watch-dir) once, report only, and exit
  --rearm-canaries          verify and recreate canary files, then exit
  --scan-file <PATH>        explain the binary AI verdict for PATH (a file, a folder or
                            @list.txt); prints JSON lines and never changes anything
  --check-file <PATH>       check one file with every engine and print one JSON line; read-only
  --list-startup            list what starts by itself (launch items, Run keys) and judge each one;
                            prints one JSON document and never changes anything
  --restore <ID>          restore a quarantined file by its quarantine ID
  --delete <ID>             permanently delete a quarantined file by its quarantine ID
  --set <ENGINE>=<on|off>   toggle known_bad, zip_bomb, bin_ai, process_guard, canary or
                            dry_run
  --set scan_schedule=<off|daily|weekly>
                            run a report-only scan of Downloads and Desktop on a schedule
  --allow <SHA256>          never flag the one file with this SHA-256 again (needs
                            administrator rights); with --allow-name NAME and --allow-type TYPE
  --allow-event <ID>        the same for the file of one logged detection: the SHA-256 is the one
                            this engine recorded in its own event log (what the app uses)
  --disallow <SHA256>       remove a file from the always-allowed list
  --allow-quarantined <ID>  restore a quarantined file and always allow that exact file
  --expect <SHA256>         with --allow-event or --allow-quarantined: refuse unless the recorded
                            SHA-256 is exactly this (the app passes the one it asked about)
  --list-allowed            print the always-allowed list as JSON
  --never-scan <FOLDER>     never open, move or delete what is in this folder; give its full path
                            (needs administrator rights); --never-scan-file <FILE> for one file
  --scan-again <PATH>       take a folder or file off the never-scan list
  --list-never-scan         print the never-scan list as JSON
  --help                    show this help

Options:
  --dry-run                 detect and log only; never terminate or quarantine
  --watch-dir <PATH>        watch only PATH (recursively) and place canaries there
  --quarantine-dir <PATH>   use PATH for quarantined files and their .meta.json records
  --log-file <PATH>         write threat events (JSON lines) to PATH
  --hash-list <PATH>        use PATH as the known-malware list (testing; only with --console,
                            --quick-scan, --full-scan, --check-file or --list-startup, never
                            the installed service)
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    KnownBad,
    ZipBomb,
    BinAi,
    ProcessGuard,
    Canary,
    DryRun,
}

impl Engine {
    pub const ALL: [Engine; 6] = [
        Engine::KnownBad,
        Engine::ZipBomb,
        Engine::BinAi,
        Engine::ProcessGuard,
        Engine::Canary,
        Engine::DryRun,
    ];

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "known_bad" | "knownbad" | "known_malware" | "hash" | "hashes" | "hash_list" => {
                Some(Engine::KnownBad)
            }
            "zip_bomb" | "zip" | "zipbomb" => Some(Engine::ZipBomb),
            "bin_ai" | "ai" | "onnx" | "binary_ai" => Some(Engine::BinAi),
            "process_guard" | "lotl" | "process" => Some(Engine::ProcessGuard),
            "canary" | "canaries" => Some(Engine::Canary),
            "dry_run" | "dryrun" => Some(Engine::DryRun),
            _ => None,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Engine::KnownBad => "known_bad",
            Engine::ZipBomb => "zip_bomb",
            Engine::BinAi => "bin_ai",
            Engine::ProcessGuard => "process_guard",
            Engine::Canary => "canary",
            Engine::DryRun => "dry_run",
        }
    }
}

fn parse_switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "enable" | "enabled" | "yes" => Some(true),
        "off" | "false" | "0" | "disable" | "disabled" | "no" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Service,
    Install,
    Uninstall,
    Console,
    Notifier,
    Tray,
    QuickScan,
    FullScan,
    RearmCanaries,
    ScanFile(PathBuf),
    CheckFile(PathBuf),
    ListStartup,
    Restore(String),
    Delete(String),
    Set(Engine, bool),
    SetSchedule(ScanSchedule),
    Allow(String),
    AllowEvent(String),
    Disallow(String),
    AllowQuarantined(String),
    ListAllowed,
    /// The place, and whether it must be a folder.
    NeverScan(PathBuf, bool),
    ScanAgain(PathBuf),
    ListNeverScan,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    pub mode: Mode,
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
    pub quarantine_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    /// Console and one-shot scans only: a known-malware list to use instead of the shipped one.
    pub hash_list: Option<PathBuf>,
    /// `--startup-dir` (testing, `--list-startup` only): list this one folder instead of the real places.
    pub startup_dir: Option<PathBuf>,
    /// `--allow` only: the name and detection type recorded with the entry.
    pub allow_name: Option<String>,
    pub allow_type: Option<String>,
    /// `--allow-event` and `--allow-quarantined` only: how the recorded SHA-256 must start.
    pub expect: Option<String>,
}

/// A path argument exactly as given: no trim and no lossy conversion, so a file whose name ends
/// in a space or newline, or is not UTF-8, is the one that gets used. Only missing/empty (or
/// something that looks like the next flag) is refused.
fn take_path<I: Iterator<Item = OsString>>(iter: &mut I, flag: &str) -> Result<PathBuf, String> {
    match iter.next() {
        Some(v) if !v.is_empty() && !v.as_encoded_bytes().starts_with(b"--") => Ok(v.into()),
        _ => Err(format!("{flag} requires a value")),
    }
}

fn take_value<I: Iterator<Item = OsString>>(iter: &mut I, flag: &str) -> Result<String, String> {
    let value = iter
        .next()
        .map(|v| v.to_string_lossy().trim().to_string())
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if value.is_empty() || value.starts_with("--") {
        return Err(format!("{flag} requires a value"));
    }
    Ok(value)
}

pub fn parse_args<I>(args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut mode: Option<Mode> = None;
    let mut dry_run = false;
    let mut watch_dir: Option<PathBuf> = None;
    let mut quarantine_dir: Option<PathBuf> = None;
    let mut log_file: Option<PathBuf> = None;
    let mut hash_list: Option<PathBuf> = None;
    let mut startup_dir: Option<PathBuf> = None;
    let mut allow_name: Option<String> = None;
    let mut allow_type: Option<String> = None;
    let mut expect: Option<String> = None;
    let mut iter = args.into_iter();

    while let Some(raw) = iter.next() {
        let arg = raw.to_string_lossy().to_string();
        let selected = match arg.as_str() {
            "--install" => Some(Mode::Install),
            "--uninstall" => Some(Mode::Uninstall),
            "--console" => Some(Mode::Console),
            "--notifier" => Some(Mode::Notifier),
            "--tray" => Some(Mode::Tray),
            "--quick-scan" => Some(Mode::QuickScan),
            "--full-scan" => Some(Mode::FullScan),
            "--rearm-canaries" => Some(Mode::RearmCanaries),
            "--help" | "-h" | "/?" => Some(Mode::Help),
            "--restore" => Some(Mode::Restore(take_value(&mut iter, "--restore")?)),
            "--delete" => Some(Mode::Delete(take_value(&mut iter, "--delete")?)),
            "--scan-file" => Some(Mode::ScanFile(take_path(&mut iter, "--scan-file")?)),
            "--check-file" => Some(Mode::CheckFile(take_path(&mut iter, "--check-file")?)),
            "--list-startup" => Some(Mode::ListStartup),
            "--startup-dir" => {
                startup_dir = Some(take_path(&mut iter, "--startup-dir")?);
                None
            }
            "--allow" => Some(Mode::Allow(allowlist::parse_sha256(&take_value(
                &mut iter, "--allow",
            )?)?)),
            "--allow-event" => {
                let id = take_value(&mut iter, "--allow-event")?;
                if !crate::quarantine::is_valid_id(&id) {
                    return Err(format!("invalid event ID: {id}"));
                }
                Some(Mode::AllowEvent(id))
            }
            "--disallow" => Some(Mode::Disallow(allowlist::parse_sha256(&take_value(
                &mut iter,
                "--disallow",
            )?)?)),
            "--allow-quarantined" => Some(Mode::AllowQuarantined(take_value(
                &mut iter,
                "--allow-quarantined",
            )?)),
            "--list-allowed" => Some(Mode::ListAllowed),
            "--never-scan" => Some(Mode::NeverScan(take_path(&mut iter, "--never-scan")?, true)),
            "--never-scan-file" => Some(Mode::NeverScan(
                take_path(&mut iter, "--never-scan-file")?,
                false,
            )),
            "--scan-again" => Some(Mode::ScanAgain(take_path(&mut iter, "--scan-again")?)),
            "--list-never-scan" => Some(Mode::ListNeverScan),
            "--allow-name" => {
                let name = take_value(&mut iter, "--allow-name")?;
                allowlist::check_name(&name)?;
                allow_name = Some(name);
                None
            }
            "--allow-type" => {
                let kind = take_value(&mut iter, "--allow-type")?;
                allowlist::check_type(&kind)?;
                allow_type = Some(kind);
                None
            }
            "--expect" => {
                let value = take_value(&mut iter, "--expect")?;
                expect =
                    Some(allowlist::parse_sha256(&value).map_err(|e| format!("--expect: {e}"))?);
                None
            }
            "--set" => {
                let value = take_value(&mut iter, "--set")?;
                let (name, state) = value.split_once('=').ok_or("--set expects ENGINE=on|off")?;
                if name.trim() == "scan_schedule" {
                    let schedule = ScanSchedule::parse(state)
                        .ok_or_else(|| format!("expected off, daily or weekly, got {state}"))?;
                    Some(Mode::SetSchedule(schedule))
                } else {
                    let engine =
                        Engine::parse(name).ok_or_else(|| format!("unknown engine: {name}"))?;
                    let enabled = parse_switch(state)
                        .ok_or_else(|| format!("expected on or off, got {state}"))?;
                    Some(Mode::Set(engine, enabled))
                }
            }
            "--dry-run" => {
                dry_run = true;
                None
            }
            "--watch-dir" => {
                watch_dir = Some(PathBuf::from(take_value(&mut iter, "--watch-dir")?));
                None
            }
            "--quarantine-dir" => {
                quarantine_dir = Some(PathBuf::from(take_value(&mut iter, "--quarantine-dir")?));
                None
            }
            "--log-file" => {
                log_file = Some(PathBuf::from(take_value(&mut iter, "--log-file")?));
                None
            }
            "--hash-list" => {
                hash_list = Some(PathBuf::from(take_value(&mut iter, "--hash-list")?));
                None
            }
            other => return Err(format!("unknown argument: {other}")),
        };
        if let Some(next) = selected {
            if mode.as_ref().is_some_and(|current| *current != next) {
                return Err("only one mode may be given".into());
            }
            mode = Some(next);
        }
    }

    let scan_options = dry_run || watch_dir.is_some();
    let path_overrides = quarantine_dir.is_some() || log_file.is_some();
    let mode = match mode {
        Some(m) => m,
        None if scan_options || path_overrides || hash_list.is_some() => Mode::Console,
        None => Mode::Service,
    };
    if scan_options && !matches!(mode, Mode::Console | Mode::QuickScan | Mode::FullScan) {
        return Err(
            "--dry-run and --watch-dir are only valid with --console, --quick-scan or --full-scan"
                .into(),
        );
    }
    // The installed service takes no arguments, so it can only ever load the list its build
    // was made with; a list named on a command line decides what gets quarantined.
    // --check-file only reports, so a list named for it cannot steer anything being quarantined.
    if hash_list.is_some()
        && !matches!(
            mode,
            Mode::Console
                | Mode::QuickScan
                | Mode::FullScan
                | Mode::CheckFile(_)
                | Mode::ListStartup
        )
    {
        return Err(
            "--hash-list is only valid with --console, --quick-scan, --full-scan, --check-file or --list-startup"
                .into(),
        );
    }
    if startup_dir.is_some() && mode != Mode::ListStartup {
        return Err("--startup-dir is only valid with --list-startup".into());
    }
    if (allow_name.is_some() || allow_type.is_some()) && !matches!(mode, Mode::Allow(_)) {
        return Err("--allow-name and --allow-type are only valid with --allow".into());
    }
    if expect.is_some() && !matches!(mode, Mode::AllowEvent(_) | Mode::AllowQuarantined(_)) {
        return Err("--expect is only valid with --allow-event or --allow-quarantined".into());
    }
    if path_overrides && matches!(mode, Mode::Install | Mode::Uninstall | Mode::Help) {
        return Err("--quarantine-dir and --log-file cannot be combined with that mode".into());
    }
    Ok(CliArgs {
        mode,
        dry_run,
        watch_dir,
        quarantine_dir,
        log_file,
        hash_list,
        startup_dir,
        allow_name,
        allow_type,
        expect,
    })
}

/// Engine switches persisted to settings.json and hot-reloaded by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeToggles {
    pub known_bad_enabled: bool,
    pub zip_bomb_enabled: bool,
    pub bin_ai_enabled: bool,
    pub process_guard_enabled: bool,
    pub canary_enabled: bool,
    pub dry_run: bool,
    /// Missing in files from before the schedule existed: off.
    #[serde(deserialize_with = "schedule::lenient")]
    pub scan_schedule: ScanSchedule,
}

impl Default for RuntimeToggles {
    fn default() -> Self {
        Self {
            known_bad_enabled: true,
            zip_bomb_enabled: true,
            bin_ai_enabled: true,
            process_guard_enabled: true,
            canary_enabled: true,
            dry_run: false,
            scan_schedule: ScanSchedule::Off,
        }
    }
}

impl RuntimeToggles {
    pub fn get(&self, engine: Engine) -> bool {
        match engine {
            Engine::KnownBad => self.known_bad_enabled,
            Engine::ZipBomb => self.zip_bomb_enabled,
            Engine::BinAi => self.bin_ai_enabled,
            Engine::ProcessGuard => self.process_guard_enabled,
            Engine::Canary => self.canary_enabled,
            Engine::DryRun => self.dry_run,
        }
    }

    pub fn set(&mut self, engine: Engine, enabled: bool) {
        match engine {
            Engine::KnownBad => self.known_bad_enabled = enabled,
            Engine::ZipBomb => self.zip_bomb_enabled = enabled,
            Engine::BinAi => self.bin_ai_enabled = enabled,
            Engine::ProcessGuard => self.process_guard_enabled = enabled,
            Engine::Canary => self.canary_enabled = enabled,
            Engine::DryRun => self.dry_run = enabled,
        }
    }

    /// Missing file means defaults; a corrupt file is an error so it is never silently reset.
    pub fn load(path: &Path) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let body = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        write_atomic(path, &body)
    }

    /// Load, change and save under one lock: the app's switches and the schedule are changed
    /// by separate commands, and an unlocked read-modify-write would lose one of two changes
    /// made at the same moment. (Within this process; the elevated `--set` is a one-off.)
    pub fn update(path: &Path, change: impl FnOnce(&mut Self)) -> io::Result<Self> {
        static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut toggles = Self::load(path)?;
        change(&mut toggles);
        toggles.save(path)?;
        Ok(toggles)
    }
}

/// A staging file older than this was left by a crash (a write takes milliseconds).
const STALE_STAGING: Duration = Duration::from_secs(60);

fn staging_path(path: &Path, n: u64) -> PathBuf {
    path.with_extension(format!("json.{}-{n}.tmp", std::process::id()))
}

/// Removes the staging files of earlier writes of `path` that a crash left behind.
fn sweep_staging(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().is_ok_and(|age| age > STALE_STAGING));
        if file.starts_with(&prefix) && file.ends_with(".tmp") && old {
            let _ = fs::remove_file(entry.path());
        }
    }
}

static STAGING: AtomicU64 = AtomicU64::new(0);

/// Writes `body` to a staging file and renames it over `path`, so a reader never sees half of it.
pub fn write_atomic(path: &Path, body: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    sweep_staging(path);
    // A name of its own, created exclusively: a leftover or planted file is never written
    // through (a taken name is skipped).
    let mut attempts = 0;
    let (staging, mut file) = loop {
        let staging = staging_path(path, STAGING.fetch_add(1, Ordering::Relaxed));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&staging) {
            Ok(file) => break (staging, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempts < 16 => attempts += 1,
            Err(e) => return Err(e),
        }
    };
    let written = (|| {
        io::Write::write_all(&mut file, body)?;
        // Whatever the umask: the allowed-files list is refused when others can write it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        drop(file);
        fs::rename(&staging, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&staging);
    }
    written
}

fn modified_nanos(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Lock-free view of [`RuntimeToggles`] shared by every detector thread.
#[derive(Debug)]
pub struct LiveToggles {
    known_bad: AtomicBool,
    zip_bomb: AtomicBool,
    bin_ai: AtomicBool,
    process_guard: AtomicBool,
    canary: AtomicBool,
    dry_run: AtomicBool,
    scan_schedule: AtomicU8,
    loaded_mtime: AtomicU64,
}

impl LiveToggles {
    pub fn new(toggles: RuntimeToggles) -> Self {
        let live = Self {
            known_bad: AtomicBool::new(true),
            zip_bomb: AtomicBool::new(true),
            bin_ai: AtomicBool::new(true),
            process_guard: AtomicBool::new(true),
            canary: AtomicBool::new(true),
            dry_run: AtomicBool::new(false),
            scan_schedule: AtomicU8::new(0),
            loaded_mtime: AtomicU64::new(0),
        };
        live.apply(toggles);
        live
    }

    pub fn load(path: &Path) -> Self {
        let live = Self::new(RuntimeToggles::load(path).unwrap_or_default());
        live.loaded_mtime
            .store(modified_nanos(path), Ordering::SeqCst);
        live
    }

    pub fn apply(&self, toggles: RuntimeToggles) {
        self.known_bad
            .store(toggles.known_bad_enabled, Ordering::SeqCst);
        self.zip_bomb
            .store(toggles.zip_bomb_enabled, Ordering::SeqCst);
        self.bin_ai.store(toggles.bin_ai_enabled, Ordering::SeqCst);
        self.process_guard
            .store(toggles.process_guard_enabled, Ordering::SeqCst);
        self.canary.store(toggles.canary_enabled, Ordering::SeqCst);
        self.dry_run.store(toggles.dry_run, Ordering::SeqCst);
        self.scan_schedule
            .store(toggles.scan_schedule as u8, Ordering::SeqCst);
    }

    pub fn scan_schedule(&self) -> ScanSchedule {
        ScanSchedule::from_u8(self.scan_schedule.load(Ordering::SeqCst))
    }

    pub fn snapshot(&self) -> RuntimeToggles {
        RuntimeToggles {
            known_bad_enabled: self.known_bad.load(Ordering::SeqCst),
            zip_bomb_enabled: self.zip_bomb.load(Ordering::SeqCst),
            bin_ai_enabled: self.bin_ai.load(Ordering::SeqCst),
            process_guard_enabled: self.process_guard.load(Ordering::SeqCst),
            canary_enabled: self.canary.load(Ordering::SeqCst),
            dry_run: self.dry_run.load(Ordering::SeqCst),
            scan_schedule: self.scan_schedule(),
        }
    }

    /// Re-reads settings.json when its modification time changed; returns the new values.
    pub fn reload_if_changed(&self, path: &Path) -> Option<RuntimeToggles> {
        let mtime = modified_nanos(path);
        if mtime == self.loaded_mtime.swap(mtime, Ordering::SeqCst) {
            return None;
        }
        let toggles = RuntimeToggles::load(path).ok()?;
        if toggles == self.snapshot() {
            return None;
        }
        self.apply(toggles);
        Some(toggles)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ZipLimits {
    pub max_ratio: f64,
    pub max_uncompressed_bytes: u64,
    pub max_depth: u32,
    pub max_nested_mem_read: u64,
    pub min_ratio_check_bytes: u64,
}

impl Default for ZipLimits {
    fn default() -> Self {
        Self {
            max_ratio: MAX_ZIP_RATIO,
            max_uncompressed_bytes: MAX_UNCOMPRESSED_BYTES,
            max_depth: MAX_ZIP_DEPTH,
            max_nested_mem_read: MAX_NESTED_MEM_READ,
            min_ratio_check_bytes: MIN_RATIO_CHECK_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub log_dir: PathBuf,
    pub events_log: PathBuf,
    pub settings_file: PathBuf,
    /// Files the AI and zip-bomb engines must leave alone (see `allowlist`).
    pub allowed_file: PathBuf,
    pub allowed: Arc<LiveAllowed>,
    /// Folders and files that are never opened, moved or deleted (see `skiplist`).
    pub skipped_file: PathBuf,
    pub skipped: Arc<LiveSkipped>,
    pub status_file: PathBuf,
    pub model_path: PathBuf,
    /// Forced dry run from the command line (settings.json can also enable it).
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
    /// Console mode: echo logs to stderr and raise desktop notifications directly.
    pub interactive: bool,
    /// Events are logged but raise no notification (see `ThreatEvent::quiet`).
    pub quiet_events: bool,
    pub zip_limits: ZipLimits,
    pub ai_threshold: f32,
    pub max_ai_scan_bytes: u64,
    pub toggles: Arc<LiveToggles>,
    /// `--hash-list`: use this list instead of the shipped one.
    pub hash_list: Option<PathBuf>,
    /// Empty until `load_known_bad` runs.
    pub known_bad: Arc<KnownBad>,
    /// Set for a scheduled scan only: findings an earlier scheduled scan already reported (and
    /// that are unchanged) are not logged again as new threat events.
    pub repeats: Option<Arc<schedule::SeenFindings>>,
}

impl AppConfig {
    pub fn for_base_dir(base_dir: &Path) -> Self {
        let log_dir = base_dir.join(LOG_DIR_NAME);
        let settings_file = base_dir.join(SETTINGS_FILE_NAME);
        let allowed_file = base_dir.join(allowlist::FILE_NAME);
        let skipped_file = base_dir.join(skiplist::FILE_NAME);
        Self {
            base_dir: base_dir.to_path_buf(),
            quarantine_dir: base_dir.join(QUARANTINE_DIR_NAME),
            events_log: log_dir.join(EVENTS_FILE_NAME),
            status_file: log_dir.join(STATUS_FILE_NAME),
            log_dir,
            toggles: Arc::new(LiveToggles::load(&settings_file)),
            settings_file,
            allowed: Arc::new(LiveAllowed::new(allowed_file.clone())),
            allowed_file,
            skipped: Arc::new(LiveSkipped::new(skipped_file.clone())),
            skipped_file,
            model_path: resolve_model_path(base_dir),
            dry_run: false,
            watch_dir: None,
            interactive: false,
            quiet_events: false,
            zip_limits: ZipLimits::default(),
            ai_threshold: AI_MALWARE_THRESHOLD,
            max_ai_scan_bytes: MAX_AI_SCAN_BYTES,
            hash_list: None,
            known_bad: Arc::new(KnownBad::empty()),
            repeats: None,
        }
    }

    /// Default data directory, honouring THENEX_DATA_DIR.
    pub fn system() -> Self {
        Self::for_base_dir(&data_dir())
    }

    pub fn from_cli(args: &CliArgs) -> Self {
        Self::from_cli_at(args, &data_dir())
    }

    /// For the notifier and tray, which run in the user's session: like `from_cli`, but
    /// THENEX_DATA_DIR is ignored once the background service is installed (see `app_data_dir`).
    pub fn from_cli_in_session(args: &CliArgs) -> Self {
        Self::from_cli_at(args, &app_data_dir())
    }

    fn from_cli_at(args: &CliArgs, base_dir: &Path) -> Self {
        let mut cfg = Self::for_base_dir(base_dir);
        cfg.dry_run = args.dry_run;
        cfg.watch_dir = args.watch_dir.as_deref().map(absolutize);
        cfg.interactive = args.mode == Mode::Console;
        cfg.hash_list = args.hash_list.as_deref().map(absolutize);

        if args.mode == Mode::Console && cfg.ensure_base_dirs().is_err() {
            if let Some(fallback) = user_fallback_base_dir() {
                let rebased = cfg.rebased(&fallback);
                if rebased.ensure_base_dirs().is_ok() {
                    cfg = rebased;
                }
            }
        }
        cfg.with_overrides(args.quarantine_dir.as_deref(), args.log_file.as_deref())
    }

    /// Applies --quarantine-dir / --log-file; the event log's folder also receives thenex.log and status.json.
    pub fn with_overrides(
        mut self,
        quarantine_dir: Option<&Path>,
        log_file: Option<&Path>,
    ) -> Self {
        if let Some(dir) = quarantine_dir {
            self.quarantine_dir = absolutize(dir);
        }
        if let Some(file) = log_file {
            let file = absolutize(file);
            self.log_dir = file
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.log_dir.clone());
            self.status_file = self.log_dir.join(STATUS_FILE_NAME);
            self.events_log = file;
        }
        self
    }

    /// Same settings with data directories under `base_dir`; keeps an existing model path.
    pub fn rebased(&self, base_dir: &Path) -> Self {
        let mut next = Self::for_base_dir(base_dir);
        if self.model_path.is_file() {
            next.model_path = self.model_path.clone();
        }
        next.dry_run = self.dry_run;
        next.watch_dir = self.watch_dir.clone();
        next.interactive = self.interactive;
        next.zip_limits = self.zip_limits;
        next.ai_threshold = self.ai_threshold;
        next.max_ai_scan_bytes = self.max_ai_scan_bytes;
        next.hash_list = self.hash_list.clone();
        next.known_bad = Arc::clone(&self.known_bad);
        next
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run || self.toggles.snapshot().dry_run
    }

    pub fn engine_enabled(&self, engine: Engine) -> bool {
        self.toggles.snapshot().get(engine)
    }

    /// True when this exact content is always allowed. A known-malware hash never is, whatever
    /// the list says. Checks the list file's stamp first, so a change counts at once.
    pub fn is_allowed(&self, digest: &Digest32) -> bool {
        self.allowed.refresh();
        self.allowed.contains(&crate::quarantine::to_hex(digest))
            && !self.known_bad.contains(digest)
    }

    /// True when the owner said never to scan this path (see `skiplist`).
    pub fn is_skipped(&self, path: &Path) -> bool {
        self.skipped.covers(path)
    }

    /// True when files should be looked up in the known-malware list.
    pub fn known_bad_active(&self) -> bool {
        !self.known_bad.is_empty() && self.engine_enabled(Engine::KnownBad)
    }

    /// Loads the known-malware list: `--hash-list` when given, otherwise the list this build
    /// was made with. A build made without one runs with an empty list, which is not an error.
    /// On error the list stays empty and every other engine keeps working.
    pub fn load_known_bad(&mut self) -> Result<(), String> {
        let (path, loaded) = match &self.hash_list {
            Some(path) => (path.clone(), KnownBad::load(path)),
            None if !known_bad::ships_list() => return Ok(()),
            None => {
                // Never the working folder: a privileged one-shot scan started from a folder
                // someone else can write to would map their file, and a mapped file can be
                // rewritten after it has passed the checksum.
                let path = resolve_data_file(&self.base_dir, known_bad::FILE_NAME, false);
                let loaded = KnownBad::load_shipped(&path);
                (path, loaded)
            }
        };
        match loaded {
            Ok(list) => {
                self.known_bad = Arc::new(list);
                Ok(())
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn ensure_base_dirs(&self) -> Result<(), String> {
        for dir in [&self.base_dir, &self.quarantine_dir, &self.log_dir] {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_log)
            .map(|_| ())
            .map_err(|e| format!("cannot write {}: {e}", self.events_log.display()))
    }

    pub fn ensure_dirs(&self) -> Result<(), String> {
        if let Some(watch) = &self.watch_dir {
            fs::create_dir_all(watch)
                .map_err(|e| format!("cannot create {}: {e}", watch.display()))?;
        }
        self.ensure_base_dirs()
    }
}

pub fn resolve_model_path(base_dir: &Path) -> PathBuf {
    resolve_data_file(base_dir, MODEL_FILE_NAME, true)
}

/// A file shipped with the app: in the data folder, the working folder (`working_dir`), or
/// next to the program.
fn resolve_data_file(base_dir: &Path, name: &str, working_dir: bool) -> PathBuf {
    let primary = base_dir.join(name);
    let mut candidates = vec![primary.clone()];
    if let Some(cwd) = std::env::current_dir().ok().filter(|_| working_dir) {
        candidates.push(cwd.join(name));
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(exe_dir.join(name));
        // TheNex.app/Contents/MacOS/the-nex -> TheNex.app/Contents/Resources/
        #[cfg(target_os = "macos")]
        candidates.push(exe_dir.join("..").join("Resources").join(name));
    }
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .unwrap_or(primary)
}

fn absolutize(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// True when running as root (Unix), or on Windows with an elevated token (UAC "run as
/// administrator") or as a machine account such as SYSTEM (account name ends in `$`).
pub fn running_privileged() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").is_ok_and(|u| u.ends_with('$')) || windows_token_elevated()
    }
}

/// Unverified on CI (Windows only): fails closed, so an unreadable token counts as elevated.
#[cfg(windows)]
fn windows_token_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: plain Win32 calls on the current process token with correctly sized out buffers;
    // the token handle is closed before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return true;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok == 0 || elevation.TokenIsElevated != 0
    }
}

/// The data folder for these inputs. THENEX_DATA_DIR is honoured only for unprivileged runs: a
/// privileged daemon must not be redirected to attacker-chosen storage through its environment.
/// The desktop app also ignores it once a background service is installed, so a fake status,
/// log or settings folder cannot be shown in place of the real one.
pub fn data_dir_for(
    env: Option<std::ffi::OsString>,
    privileged: bool,
    service_installed: bool,
) -> PathBuf {
    env.filter(|v| !v.is_empty() && !privileged && !service_installed)
        .map(PathBuf::from)
        .unwrap_or_else(default_base_dir)
}

/// The data folder for the app and its helpers in the user's session (window, notifier, tray):
/// the environment override is ignored once the background service is installed.
pub fn app_data_dir() -> PathBuf {
    data_dir_for(
        std::env::var_os(DATA_DIR_ENV),
        running_privileged(),
        crate::platform::service_installed(),
    )
}

/// The engine's data folder: the environment override applies to unprivileged runs only.
pub fn data_dir() -> PathBuf {
    data_dir_for(std::env::var_os(DATA_DIR_ENV), running_privileged(), false)
}

#[cfg(windows)]
pub fn default_base_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("TheNex")
}

#[cfg(windows)]
fn user_fallback_base_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("TheNex"))
}

#[cfg(target_os = "macos")]
pub fn default_base_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/TheNex")
}

#[cfg(target_os = "macos")]
fn user_fallback_base_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("TheNex")
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn staging_files_are_never_written_through_and_crash_leftovers_are_swept() {
        let dir = std::env::temp_dir().join(format!("thenex-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("allowed.json");
        let victim = dir.join("victim");
        fs::write(&victim, b"precious").unwrap();
        // Planted at the names the next writes would use (other tests may take a few).
        let next = STAGING.load(Ordering::Relaxed);
        for n in next..next + 6 {
            std::os::unix::fs::symlink(&victim, staging_path(&target, n)).unwrap();
        }
        write_atomic(&target, b"new").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert_eq!(fs::read(&target).unwrap(), b"new");

        // Leftovers of a crashed write: an old one goes, a fresh one (maybe a live write) stays.
        let old = dir.join("allowed.json.4242-7.tmp");
        let fresh = dir.join("allowed.json.4242-8.tmp");
        let other = dir.join("other.json.4242-7.tmp");
        for f in [&old, &fresh, &other] {
            fs::write(f, b"x").unwrap();
        }
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - STALE_STAGING - Duration::from_secs(5))
            .unwrap();
        write_atomic(&target, b"newer").unwrap();
        assert!(!old.exists() && fresh.exists() && other.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn parse(args: &[&str]) -> Result<super::CliArgs, String> {
        super::parse_args(args.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn always_allow_options_are_parsed_strictly() {
        use super::Mode;
        let sha = "ab".repeat(32);
        let parsed = parse(&[
            "--allow",
            &sha.to_uppercase(),
            "--allow-name",
            "a b.exe",
            "--allow-type",
            "ZIP_BOMB",
        ])
        .unwrap();
        assert_eq!(parsed.mode, Mode::Allow(sha.clone()));
        assert_eq!(parsed.allow_name.as_deref(), Some("a b.exe"));
        assert_eq!(parsed.allow_type.as_deref(), Some("ZIP_BOMB"));
        assert_eq!(
            parse(&["--disallow", &sha]).unwrap().mode,
            Mode::Disallow(sha.clone())
        );
        assert_eq!(
            parse(&["--allow-quarantined", "20260101-1-0001"])
                .unwrap()
                .mode,
            Mode::AllowQuarantined("20260101-1-0001".to_string())
        );
        assert_eq!(parse(&["--list-allowed"]).unwrap().mode, Mode::ListAllowed);
        assert_eq!(
            parse(&["--never-scan", "/Users/me/a b "]).unwrap().mode,
            Mode::NeverScan("/Users/me/a b ".into(), true)
        );
        assert_eq!(
            parse(&["--never-scan-file", "/Users/me/a"]).unwrap().mode,
            Mode::NeverScan("/Users/me/a".into(), false)
        );
        assert_eq!(
            parse(&["--scan-again", "/Users/me/x"]).unwrap().mode,
            Mode::ScanAgain("/Users/me/x".into())
        );
        assert_eq!(
            parse(&["--list-never-scan"]).unwrap().mode,
            Mode::ListNeverScan
        );
        assert_eq!(
            parse(&["--allow-event", "20260101-1-0001"]).unwrap().mode,
            Mode::AllowEvent("20260101-1-0001".to_string())
        );
        for mode in ["--allow-event", "--allow-quarantined"] {
            let parsed = parse(&[mode, "x1", "--expect", &sha.to_uppercase()]).unwrap();
            assert_eq!(parsed.expect, Some(sha.to_lowercase()));
        }
        for bad in [
            vec!["--allow-event", "x", "--expect"],
            vec!["--allow-event", "x", "--expect", "abcdef0123456789"],
            vec!["--allow-event", "x", "--expect", &sha[1..]],
            vec!["--allow", &sha, "--expect", &sha],
            vec!["--expect", &sha],
            vec!["--allow-event"],
            vec!["--allow-event", "../etc"],
            vec!["--allow-event", "a b"],
            vec!["--allow-event", "x", "--allow-name", "y"],
            vec!["--allow-event", "x", "--allow", &sha],
            vec!["--allow", "abc"],
            vec!["--allow", &sha[1..]],
            vec!["--allow"],
            vec!["--disallow", "zz"],
            vec!["--never-scan"],
            vec!["--never-scan", "--dry-run"],
            vec!["--never-scan", "/Users/me/x", "--scan-again", "/Users/me/x"],
            vec!["--allow", &sha, "--allow-type", "KNOWN_MALWARE"],
            vec!["--allow", &sha, "--allow-type", "LOTL_SCRIPT"],
            vec!["--allow", &sha, "--allow-name", "bad\u{7}name"],
            vec!["--allow", &sha, "--allow-name", &"n".repeat(121)],
            vec!["--allow-name", "x"],
            vec!["--list-allowed", "--allow-type", "ZIP_BOMB"],
            vec!["--allow", &sha, "--disallow", &sha],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }
    #[test]
    fn the_data_dir_env_is_ignored_when_privileged_or_when_a_service_is_installed() {
        let env = || Some(std::ffi::OsString::from("/fake/data"));
        assert_eq!(
            super::data_dir_for(env(), false, false),
            PathBuf::from("/fake/data")
        );
        for (privileged, service) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                super::data_dir_for(env(), privileged, service),
                super::default_base_dir()
            );
        }
        let empty = Some(std::ffi::OsString::new());
        assert_eq!(
            super::data_dir_for(empty, false, false),
            super::default_base_dir()
        );
        assert_eq!(
            super::data_dir_for(None, false, false),
            super::default_base_dir()
        );
    }

    #[test]
    fn privileged_runs_ignore_the_data_dir_env() {
        // Not mutating the environment (shared across tests): just check the rule's input.
        if super::running_privileged() {
            assert_eq!(super::data_dir(), super::default_base_dir());
        }
    }

    use super::*;

    fn args(list: &[&str]) -> Result<CliArgs, String> {
        parse_args(list.iter().map(OsString::from))
    }

    #[test]
    fn no_args_is_service() {
        assert_eq!(args(&[]).unwrap().mode, Mode::Service);
    }

    #[test]
    fn console_options_imply_console() {
        let parsed = args(&["--dry-run", "--watch-dir", "sandbox"]).unwrap();
        assert_eq!(parsed.mode, Mode::Console);
        assert!(parsed.dry_run);
        assert_eq!(parsed.watch_dir, Some(PathBuf::from("sandbox")));
    }

    #[test]
    fn overrides_and_subcommands_parse() {
        let parsed = args(&[
            "--restore",
            "abc-1",
            "--quarantine-dir",
            "q",
            "--log-file",
            "l.jsonl",
        ])
        .unwrap();
        assert_eq!(parsed.mode, Mode::Restore("abc-1".into()));
        assert_eq!(parsed.quarantine_dir, Some(PathBuf::from("q")));
        assert_eq!(parsed.log_file, Some(PathBuf::from("l.jsonl")));
        assert_eq!(
            args(&["--delete", "x"]).unwrap().mode,
            Mode::Delete("x".into())
        );
        assert_eq!(args(&["--tray"]).unwrap().mode, Mode::Tray);
        assert_eq!(
            args(&["--set", "zip-bomb=off"]).unwrap().mode,
            Mode::Set(Engine::ZipBomb, false)
        );
        assert_eq!(
            args(&["--quick-scan", "--dry-run"]).unwrap().mode,
            Mode::QuickScan
        );
        assert_eq!(
            args(&["--scan-file", "setup.exe"]).unwrap().mode,
            Mode::ScanFile(PathBuf::from("setup.exe"))
        );
        assert_eq!(
            args(&["--check-file", "/tmp/a.zip"]).unwrap().mode,
            Mode::CheckFile(PathBuf::from("/tmp/a.zip"))
        );
        assert!(args(&["--check-file"]).is_err());
        assert!(args(&["--check-file", "--dry-run"]).is_err());
        assert!(args(&["--check-file", "a.zip", "--dry-run"]).is_err());
        assert_eq!(args(&["--list-startup"]).unwrap().mode, Mode::ListStartup);
        assert!(args(&["--list-startup", "--dry-run"]).is_err());
        assert!(args(&["--list-startup", "--restore", "x"]).is_err());
        let sandbox = args(&["--list-startup", "--startup-dir", "/tmp/x"]).unwrap();
        assert_eq!(sandbox.startup_dir, Some(PathBuf::from("/tmp/x")));
        assert!(
            args(&["--startup-dir", "/tmp/x"]).is_err(),
            "never for normal use"
        );
        assert!(args(&["--check-file", "a", "--startup-dir", "/tmp/x"]).is_err());
        assert!(args(&["--scan-file"]).is_err());
        assert!(args(&["--scan-file", "a.exe", "--dry-run"]).is_err());
    }

    #[test]
    fn path_arguments_are_taken_exactly_as_given() {
        for name in ["pack.zip ", "pack.zip\n", " pack.zip", " "] {
            assert_eq!(
                args(&["--check-file", name]).unwrap().mode,
                Mode::CheckFile(PathBuf::from(name))
            );
            assert_eq!(
                args(&["--scan-file", name]).unwrap().mode,
                Mode::ScanFile(PathBuf::from(name))
            );
            let sandbox = args(&["--list-startup", "--startup-dir", name]).unwrap();
            assert_eq!(sandbox.startup_dir, Some(PathBuf::from(name)));
        }
        assert!(args(&["--check-file", ""]).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = OsString::from_vec(b"bad-\xff\xfe.zip".to_vec());
            let parsed = parse_args([OsString::from("--check-file"), raw.clone()]).unwrap();
            assert_eq!(parsed.mode, Mode::CheckFile(PathBuf::from(raw)));
        }
    }

    #[test]
    fn hash_list_is_never_accepted_by_the_service_modes() {
        let parsed = args(&["--console", "--hash-list", "test.bin"]).unwrap();
        assert_eq!(parsed.hash_list, Some(PathBuf::from("test.bin")));
        assert_eq!(
            args(&["--hash-list", "test.bin"]).unwrap().mode,
            Mode::Console
        );
        assert!(args(&["--quick-scan", "--hash-list", "test.bin"]).is_ok());
        assert!(args(&["--check-file", "a.zip", "--hash-list", "test.bin"]).is_ok());
        for mode in ["--install", "--uninstall", "--notifier", "--tray"] {
            assert!(args(&[mode, "--hash-list", "test.bin"]).is_err(), "{mode}");
        }
        assert!(args(&["--set", "canary=on", "--hash-list", "test.bin"]).is_err());
        assert_eq!(args(&[]).unwrap().hash_list, None, "the service takes none");
        assert!(args(&["--console", "--hash-list"]).is_err());
        assert_eq!(
            args(&["--set", "known_bad=off"]).unwrap().mode,
            Mode::Set(Engine::KnownBad, false)
        );
        assert_eq!(Engine::parse("known-malware"), Some(Engine::KnownBad));
        for engine in Engine::ALL {
            assert_eq!(Engine::parse(engine.key()), Some(engine));
        }
    }

    #[test]
    fn the_known_malware_switch_defaults_on_and_old_settings_still_load() {
        assert!(RuntimeToggles::default().known_bad_enabled);
        // settings.json written before the switch existed
        let old: RuntimeToggles =
            serde_json::from_str(r#"{"zip_bomb_enabled":false,"dry_run":true}"#).unwrap();
        assert!(old.known_bad_enabled && !old.zip_bomb_enabled && old.dry_run);

        let dir = std::env::temp_dir().join(format!("thenex-kb-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cfg = AppConfig::for_base_dir(&dir.join("base"));
        assert!(!cfg.known_bad_active(), "no list loaded yet");

        let list = dir.join("list.bin");
        let digest = [7u8; 32];
        known_bad::write_list(&list, &[digest], 5).unwrap();
        cfg.hash_list = Some(list.clone());
        cfg.load_known_bad().unwrap();
        assert!(cfg.known_bad_active() && cfg.known_bad.contains(&digest));

        let mut toggles = cfg.toggles.snapshot();
        toggles.set(Engine::KnownBad, false);
        cfg.toggles.apply(toggles);
        assert!(!cfg.known_bad_active(), "switched off");

        // A damaged list is an error and leaves the list already loaded in place.
        let damaged = dir.join("damaged.bin");
        fs::write(&damaged, b"not a list").unwrap();
        cfg.hash_list = Some(damaged);
        let err = cfg.load_known_bad().unwrap_err();
        assert!(err.contains("damaged.bin"), "{err}");
        assert!(cfg.known_bad.contains(&digest));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_conflicts_and_unknown() {
        assert!(args(&["--restore"]).is_err());
        assert!(args(&["--install", "--console"]).is_err());
        assert!(args(&["--install", "--dry-run"]).is_err());
        assert!(args(&["--uninstall", "--log-file", "x"]).is_err());
        assert!(args(&["--set", "warp=on"]).is_err());
        assert!(args(&["--set", "canary=maybe"]).is_err());
        assert!(args(&["--bogus"]).is_err());
    }

    #[test]
    fn paths_derive_from_base_and_overrides() {
        let cfg = AppConfig::for_base_dir(Path::new("base"));
        assert_eq!(cfg.quarantine_dir, Path::new("base").join("Quarantine"));
        assert_eq!(cfg.settings_file, Path::new("base").join("settings.json"));
        assert_eq!(
            cfg.events_log,
            Path::new("base").join("logs").join("events.jsonl")
        );
        let cfg = cfg.with_overrides(Some(Path::new("q")), Some(Path::new("elsewhere/ev.jsonl")));
        assert!(cfg.quarantine_dir.ends_with("q"));
        assert!(cfg
            .events_log
            .ends_with(Path::new("elsewhere").join("ev.jsonl")));
        assert!(cfg
            .status_file
            .ends_with(Path::new("elsewhere").join("status.json")));
    }

    #[test]
    fn toggles_round_trip_and_hot_reload() {
        let dir = std::env::temp_dir().join(format!("thenex-toggles-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        assert_eq!(
            RuntimeToggles::load(&path).unwrap(),
            RuntimeToggles::default()
        );

        let live = LiveToggles::load(&path);
        let mut toggles = RuntimeToggles::default();
        toggles.set(Engine::BinAi, false);
        toggles.set(Engine::DryRun, true);
        toggles.save(&path).unwrap();
        assert_eq!(RuntimeToggles::load(&path).unwrap(), toggles);
        assert_eq!(live.reload_if_changed(&path), Some(toggles));
        assert!(!live.snapshot().bin_ai_enabled);
        assert!(live.snapshot().dry_run);
        assert_eq!(live.reload_if_changed(&path), None);

        fs::write(&path, b"{ not json").unwrap();
        assert!(RuntimeToggles::load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_updates_keep_every_change_and_the_help_names_every_mode() {
        let dir = std::env::temp_dir().join(format!("thenex-upd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        RuntimeToggles::update(&path, |t| {
                            if i % 2 == 0 {
                                t.scan_schedule = ScanSchedule::Weekly;
                            } else {
                                t.set(Engine::Canary, false);
                            }
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let t = RuntimeToggles::load(&path).unwrap();
        assert!(t.scan_schedule == ScanSchedule::Weekly && !t.canary_enabled);
        let _ = fs::remove_dir_all(&dir);
        // --hash-list is accepted with these modes (see the check in `parse`), so say so.
        for mode in [
            "--check-file",
            "--list-startup",
            "--full-scan",
            "--quick-scan",
        ] {
            assert!(USAGE.contains(mode));
        }
        let line = USAGE.split("--hash-list").nth(1).unwrap();
        assert!(line.contains("--check-file") && line.contains("--list-startup"));
    }

    #[test]
    fn two_settings_updates_never_run_at_the_same_time() {
        // The changes themselves are only ever run under the lock, so overlapping closures
        // would show it is gone (the final file alone cannot: later updates repair a lost one).
        let dir = std::env::temp_dir().join(format!("thenex-upd-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        let inside = std::sync::atomic::AtomicUsize::new(0);
        let worst = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    for _ in 0..5 {
                        RuntimeToggles::update(&path, |_| {
                            let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                            worst.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(3));
                            inside.fetch_sub(1, Ordering::SeqCst);
                        })
                        .unwrap();
                    }
                });
            }
        });
        assert_eq!(worst.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_scan_schedule_defaults_off_and_settings_files_work_both_ways() {
        assert_eq!(
            args(&["--set", "scan_schedule=weekly"]).unwrap().mode,
            Mode::SetSchedule(ScanSchedule::Weekly)
        );
        assert!(args(&["--set", "scan_schedule=hourly"]).is_err());
        assert!(args(&["--set", "scan_schedule=on"]).is_err());
        assert!(args(&["--set", "scan_schedule=daily", "--set", "canary=on"]).is_err());

        // A file from before the schedule existed, one with an unknown value, and one with a
        // setting a newer version added all load; only the known name switches it on.
        let old: RuntimeToggles = serde_json::from_str(r#"{"dry_run":true}"#).unwrap();
        assert!(old.dry_run && old.scan_schedule == ScanSchedule::Off);
        let odd: RuntimeToggles =
            serde_json::from_str(r#"{"scan_schedule":"monthly","from_the_future":1}"#).unwrap();
        assert_eq!(odd.scan_schedule, ScanSchedule::Off);
        let daily: RuntimeToggles = serde_json::from_str(r#"{"scan_schedule":"daily"}"#).unwrap();
        assert_eq!(daily.scan_schedule, ScanSchedule::Daily);

        // What an older app does with a newer file: it reads the engine switches it knows and
        // ignores the schedule (modelled by a reader that lacks the field).
        #[derive(Deserialize)]
        struct Before {
            canary_enabled: bool,
            dry_run: bool,
        }
        let json = serde_json::to_string(&daily).unwrap();
        assert!(json.contains(r#""scan_schedule":"daily""#));
        let before: Before = serde_json::from_str(&json).unwrap();
        assert!(before.canary_enabled && !before.dry_run);

        // Changing an engine switch keeps the schedule, and the service hot-reloads it.
        let dir = std::env::temp_dir().join(format!("thenex-sched-set-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        let live = LiveToggles::load(&path);
        assert_eq!(live.scan_schedule(), ScanSchedule::Off);
        daily.save(&path).unwrap();
        assert_eq!(live.reload_if_changed(&path), Some(daily));
        assert_eq!(live.scan_schedule(), ScanSchedule::Daily);
        let mut loaded = RuntimeToggles::load(&path).unwrap();
        loaded.set(Engine::Canary, false);
        loaded.save(&path).unwrap();
        assert_eq!(
            RuntimeToggles::load(&path).unwrap().scan_schedule,
            ScanSchedule::Daily
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
