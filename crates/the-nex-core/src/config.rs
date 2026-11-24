use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

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
  --rearm-canaries          verify and recreate canary files, then exit
  --scan-file <PATH>        explain the binary AI verdict for PATH (a file, a folder or
                            @list.txt); prints JSON lines and never changes anything
  --restore <ID>          restore a quarantined file by its quarantine ID
  --delete <ID>             permanently delete a quarantined file by its quarantine ID
  --set <ENGINE>=<on|off>   toggle zip_bomb, bin_ai, process_guard, canary or dry_run
  --help                    show this help

Options:
  --dry-run                 detect and log only; never terminate or quarantine
  --watch-dir <PATH>        watch only PATH (recursively) and place canaries there
  --quarantine-dir <PATH>   use PATH for quarantined files and their .meta.json records
  --log-file <PATH>         write threat events (JSON lines) to PATH
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    ZipBomb,
    BinAi,
    ProcessGuard,
    Canary,
    DryRun,
}

impl Engine {
    pub const ALL: [Engine; 5] = [
        Engine::ZipBomb,
        Engine::BinAi,
        Engine::ProcessGuard,
        Engine::Canary,
        Engine::DryRun,
    ];

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().replace('-', "_").as_str() {
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
    RearmCanaries,
    ScanFile(PathBuf),
    Restore(String),
    Delete(String),
    Set(Engine, bool),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    pub mode: Mode,
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
    pub quarantine_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
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
            "--rearm-canaries" => Some(Mode::RearmCanaries),
            "--help" | "-h" | "/?" => Some(Mode::Help),
            "--restore" => Some(Mode::Restore(take_value(&mut iter, "--restore")?)),
            "--delete" => Some(Mode::Delete(take_value(&mut iter, "--delete")?)),
            "--scan-file" => Some(Mode::ScanFile(PathBuf::from(take_value(
                &mut iter,
                "--scan-file",
            )?))),
            "--set" => {
                let value = take_value(&mut iter, "--set")?;
                let (name, state) = value.split_once('=').ok_or("--set expects ENGINE=on|off")?;
                let engine =
                    Engine::parse(name).ok_or_else(|| format!("unknown engine: {name}"))?;
                let enabled = parse_switch(state)
                    .ok_or_else(|| format!("expected on or off, got {state}"))?;
                Some(Mode::Set(engine, enabled))
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
        None if scan_options || path_overrides => Mode::Console,
        None => Mode::Service,
    };
    if scan_options && !matches!(mode, Mode::Console | Mode::QuickScan) {
        return Err(
            "--dry-run and --watch-dir are only valid with --console or --quick-scan".into(),
        );
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
    })
}

/// Engine switches persisted to settings.json and hot-reloaded by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeToggles {
    pub zip_bomb_enabled: bool,
    pub bin_ai_enabled: bool,
    pub process_guard_enabled: bool,
    pub canary_enabled: bool,
    pub dry_run: bool,
}

impl Default for RuntimeToggles {
    fn default() -> Self {
        Self {
            zip_bomb_enabled: true,
            bin_ai_enabled: true,
            process_guard_enabled: true,
            canary_enabled: true,
            dry_run: false,
        }
    }
}

impl RuntimeToggles {
    pub fn get(&self, engine: Engine) -> bool {
        match engine {
            Engine::ZipBomb => self.zip_bomb_enabled,
            Engine::BinAi => self.bin_ai_enabled,
            Engine::ProcessGuard => self.process_guard_enabled,
            Engine::Canary => self.canary_enabled,
            Engine::DryRun => self.dry_run,
        }
    }

    pub fn set(&mut self, engine: Engine, enabled: bool) {
        match engine {
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let staging = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(&staging, body)?;
        fs::rename(&staging, path)
    }
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
    zip_bomb: AtomicBool,
    bin_ai: AtomicBool,
    process_guard: AtomicBool,
    canary: AtomicBool,
    dry_run: AtomicBool,
    loaded_mtime: AtomicU64,
}

impl LiveToggles {
    pub fn new(toggles: RuntimeToggles) -> Self {
        let live = Self {
            zip_bomb: AtomicBool::new(true),
            bin_ai: AtomicBool::new(true),
            process_guard: AtomicBool::new(true),
            canary: AtomicBool::new(true),
            dry_run: AtomicBool::new(false),
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
        self.zip_bomb
            .store(toggles.zip_bomb_enabled, Ordering::SeqCst);
        self.bin_ai.store(toggles.bin_ai_enabled, Ordering::SeqCst);
        self.process_guard
            .store(toggles.process_guard_enabled, Ordering::SeqCst);
        self.canary.store(toggles.canary_enabled, Ordering::SeqCst);
        self.dry_run.store(toggles.dry_run, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> RuntimeToggles {
        RuntimeToggles {
            zip_bomb_enabled: self.zip_bomb.load(Ordering::SeqCst),
            bin_ai_enabled: self.bin_ai.load(Ordering::SeqCst),
            process_guard_enabled: self.process_guard.load(Ordering::SeqCst),
            canary_enabled: self.canary.load(Ordering::SeqCst),
            dry_run: self.dry_run.load(Ordering::SeqCst),
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
    pub status_file: PathBuf,
    pub model_path: PathBuf,
    /// Forced dry run from the command line (settings.json can also enable it).
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
    /// Console mode: echo logs to stderr and raise desktop notifications directly.
    pub interactive: bool,
    pub zip_limits: ZipLimits,
    pub ai_threshold: f32,
    pub max_ai_scan_bytes: u64,
    pub toggles: Arc<LiveToggles>,
}

impl AppConfig {
    pub fn for_base_dir(base_dir: &Path) -> Self {
        let log_dir = base_dir.join(LOG_DIR_NAME);
        let settings_file = base_dir.join(SETTINGS_FILE_NAME);
        Self {
            base_dir: base_dir.to_path_buf(),
            quarantine_dir: base_dir.join(QUARANTINE_DIR_NAME),
            events_log: log_dir.join(EVENTS_FILE_NAME),
            status_file: log_dir.join(STATUS_FILE_NAME),
            log_dir,
            toggles: Arc::new(LiveToggles::load(&settings_file)),
            settings_file,
            model_path: resolve_model_path(base_dir),
            dry_run: false,
            watch_dir: None,
            interactive: false,
            zip_limits: ZipLimits::default(),
            ai_threshold: AI_MALWARE_THRESHOLD,
            max_ai_scan_bytes: MAX_AI_SCAN_BYTES,
        }
    }

    /// Default data directory, honouring THENEX_DATA_DIR.
    pub fn system() -> Self {
        Self::for_base_dir(&data_dir())
    }

    pub fn from_cli(args: &CliArgs) -> Self {
        let mut cfg = Self::system();
        cfg.dry_run = args.dry_run;
        cfg.watch_dir = args.watch_dir.as_deref().map(absolutize);
        cfg.interactive = args.mode == Mode::Console;

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
        next
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run || self.toggles.snapshot().dry_run
    }

    pub fn engine_enabled(&self, engine: Engine) -> bool {
        self.toggles.snapshot().get(engine)
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
    let primary = base_dir.join(MODEL_FILE_NAME);
    let mut candidates = vec![primary.clone()];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(MODEL_FILE_NAME));
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(exe_dir.join(MODEL_FILE_NAME));
        // TheNex.app/Contents/MacOS/the-nex -> TheNex.app/Contents/Resources/
        #[cfg(target_os = "macos")]
        candidates.push(exe_dir.join("..").join("Resources").join(MODEL_FILE_NAME));
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
fn running_privileged() -> bool {
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

/// Default data directory. THENEX_DATA_DIR is honoured only for unprivileged runs: a privileged
/// daemon must not be redirected to attacker-chosen storage through its environment.
pub fn data_dir() -> PathBuf {
    std::env::var_os(DATA_DIR_ENV)
        .filter(|v| !v.is_empty() && !running_privileged())
        .map(PathBuf::from)
        .unwrap_or_else(default_base_dir)
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
        assert!(args(&["--scan-file"]).is_err());
        assert!(args(&["--scan-file", "a.exe", "--dry-run"]).is_err());
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
}
