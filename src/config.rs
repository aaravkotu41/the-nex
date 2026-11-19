use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

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

pub const USAGE: &str = "\
Usage: the-nex [MODE] [OPTIONS]

Modes:
  (no arguments)        run as the native background service
  --install             register the service and the per-user notifier (Administrator)
  --uninstall           remove the service, notifier autostart and canaries (Administrator)
  --console             run the protection engine in this console
  --notifier            show desktop notifications for new threat events
  --restore <ID>        restore a quarantined file by its quarantine ID (Administrator)
  --help                show this help

Console options:
  --dry-run             detect and log only; never terminate or quarantine
  --watch-dir <PATH>    watch only PATH (recursively) and place canaries there
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Service,
    Install,
    Uninstall,
    Console,
    Notifier,
    Restore(String),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    pub mode: Mode,
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
}

pub fn parse_args<I>(args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut mode: Option<Mode> = None;
    let mut dry_run = false;
    let mut watch_dir: Option<PathBuf> = None;
    let mut iter = args.into_iter();

    while let Some(raw) = iter.next() {
        let arg = raw.to_string_lossy().to_string();
        let selected = match arg.as_str() {
            "--install" => Some(Mode::Install),
            "--uninstall" => Some(Mode::Uninstall),
            "--console" => Some(Mode::Console),
            "--notifier" => Some(Mode::Notifier),
            "--help" | "-h" | "/?" => Some(Mode::Help),
            "--restore" => {
                let id = iter.next().ok_or("--restore requires a quarantine ID")?;
                let id = id.to_string_lossy().trim().to_string();
                if id.is_empty() || id.starts_with("--") {
                    return Err("--restore requires a quarantine ID".into());
                }
                Some(Mode::Restore(id))
            }
            "--dry-run" => {
                dry_run = true;
                None
            }
            "--watch-dir" => {
                let dir = iter.next().ok_or("--watch-dir requires a path")?;
                if dir.to_string_lossy().starts_with("--") {
                    return Err("--watch-dir requires a path".into());
                }
                watch_dir = Some(PathBuf::from(dir));
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

    let console_options = dry_run || watch_dir.is_some();
    let mode = match mode {
        Some(m) => m,
        None if console_options => Mode::Console,
        None => Mode::Service,
    };
    if console_options && mode != Mode::Console {
        return Err("--dry-run and --watch-dir are only valid in console mode".into());
    }
    Ok(CliArgs {
        mode,
        dry_run,
        watch_dir,
    })
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
    pub model_path: PathBuf,
    pub dry_run: bool,
    pub watch_dir: Option<PathBuf>,
    /// Console mode: echo logs to stderr and raise desktop notifications directly.
    pub interactive: bool,
    pub zip_limits: ZipLimits,
    pub ai_threshold: f32,
    pub max_ai_scan_bytes: u64,
}

impl AppConfig {
    pub fn for_base_dir(base_dir: &Path) -> Self {
        let log_dir = base_dir.join(LOG_DIR_NAME);
        Self {
            base_dir: base_dir.to_path_buf(),
            quarantine_dir: base_dir.join(QUARANTINE_DIR_NAME),
            events_log: log_dir.join(EVENTS_FILE_NAME),
            log_dir,
            model_path: resolve_model_path(base_dir),
            dry_run: false,
            watch_dir: None,
            interactive: false,
            zip_limits: ZipLimits::default(),
            ai_threshold: AI_MALWARE_THRESHOLD,
            max_ai_scan_bytes: MAX_AI_SCAN_BYTES,
        }
    }

    pub fn from_cli(args: &CliArgs) -> Self {
        let mut cfg = Self::for_base_dir(&default_base_dir());
        cfg.dry_run = args.dry_run;
        cfg.watch_dir = args.watch_dir.as_deref().map(absolutize);
        cfg.interactive = args.mode == Mode::Console;

        if args.mode == Mode::Console && cfg.ensure_dirs().is_err() {
            if let Some(fallback) = user_fallback_base_dir() {
                let rebased = cfg.rebased(&fallback);
                if rebased.ensure_dirs().is_ok() {
                    cfg = rebased;
                }
            }
        }
        cfg
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

    pub fn ensure_dirs(&self) -> Result<(), String> {
        let mut dirs = vec![&self.base_dir, &self.quarantine_dir, &self.log_dir];
        if let Some(watch) = &self.watch_dir {
            dirs.push(watch);
        }
        for dir in dirs {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_log)
            .map(|_| ())
            .map_err(|e| format!("cannot write {}: {e}", self.events_log.display()))
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
    fn restore_takes_id() {
        assert_eq!(
            args(&["--restore", "abc-1"]).unwrap().mode,
            Mode::Restore("abc-1".into())
        );
        assert!(args(&["--restore"]).is_err());
    }

    #[test]
    fn rejects_conflicts_and_unknown() {
        assert!(args(&["--install", "--console"]).is_err());
        assert!(args(&["--install", "--dry-run"]).is_err());
        assert!(args(&["--bogus"]).is_err());
    }

    #[test]
    fn paths_derive_from_base() {
        let cfg = AppConfig::for_base_dir(Path::new("base"));
        assert_eq!(cfg.quarantine_dir, Path::new("base").join("Quarantine"));
        assert_eq!(
            cfg.events_log,
            Path::new("base").join("logs").join("events.jsonl")
        );
    }
}
