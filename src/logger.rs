use chrono::{SecondsFormat, Utc};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

const LOG_FILE_NAME: &str = "thenex.log";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

struct LoggerState {
    file: Option<PathBuf>,
    echo: bool,
}

static STATE: Mutex<LoggerState> = Mutex::new(LoggerState {
    file: None,
    echo: true,
});

pub fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn init(log_dir: &Path, echo: bool) {
    let mut state = lock_or_recover(&STATE);
    state.file = Some(log_dir.join(LOG_FILE_NAME));
    state.echo = echo;
}

pub fn init_without_file(echo: bool) {
    let mut state = lock_or_recover(&STATE);
    state.file = None;
    state.echo = echo;
}

pub fn info(msg: impl AsRef<str>) {
    write("INFO", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    write("WARN", msg.as_ref());
}

pub fn error(msg: impl AsRef<str>) {
    write("ERROR", msg.as_ref());
}

fn write(level: &str, msg: &str) {
    let line = format!(
        "{} [{level}] {msg}\n",
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    );
    let state = lock_or_recover(&STATE);
    if state.echo {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if let Some(path) = state.file.as_ref() {
        rotate_if_needed(path);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn rotate_if_needed(path: &Path) {
    if fs::metadata(path)
        .map(|m| m.len() > MAX_LOG_BYTES)
        .unwrap_or(false)
    {
        let rotated = path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(path, &rotated);
    }
}
