//! The "Startup" page's check. The page has one button and no arguments: nothing it sends can
//! choose what is read. The bundled engine (`the-nex --list-startup`) does the reading in a child
//! process with the user's own rights, a time limit and bounded output, because every startup
//! definition on disk is hostile input. It only reads; the result lives in the page's memory.

use crate::filecheck::{run_engine, Run};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use the_nex_core::platform;
use the_nex_core::startup::{StartupReport, TOTAL_LIMIT};

/// The engine stops itself at `TOTAL_LIMIT`; this is the backstop.
const TIME_LIMIT: Duration = Duration::from_secs(TOTAL_LIMIT.as_secs() + 30);
/// 500 items of a few KB each, at most.
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;

static BUSY: AtomicBool = AtomicBool::new(false);

fn check(engine: &std::path::Path, limit: Duration) -> Result<StartupReport, String> {
    if !engine.is_file() {
        return Err("The Nex's protection engine was not found next to the app, so nothing could be checked.".into());
    }
    match run_engine(engine, &["--list-startup".as_ref()], limit, MAX_OUTPUT) {
        Run::NotStarted => Err("The Nex's protection engine could not be started.".into()),
        Run::TooLong => {
            Err("Checking took too long, so it was stopped. Nothing was changed.".into())
        }
        Run::Done { ok, output } => {
            let line = output.split(|&b| b == b'\n').next().unwrap_or_default();
            match serde_json::from_slice::<StartupReport>(line) {
                Ok(mut report) if ok => {
                    report.clamp();
                    Ok(report)
                }
                _ => Err("The check could not finish, so nothing was listed.".into()),
            }
        }
    }
}

#[tauri::command]
pub async fn check_startup() -> Result<StartupReport, String> {
    if BUSY.swap(true, Ordering::SeqCst) {
        return Err("Still checking. Try again in a moment.".into());
    }
    let result = tauri::async_runtime::spawn_blocking(|| {
        check(
            &platform::sibling_executable(platform::DAEMON_EXE_STEM),
            TIME_LIMIT,
        )
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    BUSY.store(false, Ordering::SeqCst);
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Instant;

    fn fake_engine(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-st-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("engine.sh");
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    const OK_JSON: &str =
        r#"{"items":[],"unreadable":[{"place":"p","reason":"r"}],"skipped":2,"truncated":false}"#;

    #[test]
    fn the_engine_gets_exactly_one_argument_and_its_answer_is_read() {
        let engine = fake_engine("ok", &format!("[ \"$#\" = 1 ] && [ \"$1\" = --list-startup ] || exit 3\ncat <<EOF\n{OK_JSON}\nEOF"));
        let report = check(&engine, Duration::from_secs(10)).unwrap();
        assert_eq!((report.unreadable.len(), report.skipped), (1, 2));
    }

    #[test]
    fn a_slow_broken_or_missing_engine_gives_a_plain_error() {
        let started = Instant::now();
        let slow = check(&fake_engine("slow", "sleep 30"), Duration::from_millis(300));
        assert!(
            slow.unwrap_err().contains("too long") && started.elapsed() < Duration::from_secs(5)
        );
        for (tag, body) in [
            ("yes", "exec yes"),
            ("junk", "echo 'not json'"),
            ("fail", &format!("echo '{OK_JSON}'; exit 1")[..]),
            ("empty", "true"),
        ] {
            let started = Instant::now();
            let err = check(&fake_engine(tag, body), Duration::from_secs(10)).unwrap_err();
            assert!(
                err.contains("could not finish") && started.elapsed() < Duration::from_secs(8),
                "{tag}"
            );
        }
        assert!(check(
            std::path::Path::new("/nonexistent/engine"),
            Duration::from_secs(1)
        )
        .unwrap_err()
        .contains("not found"));
    }
}
