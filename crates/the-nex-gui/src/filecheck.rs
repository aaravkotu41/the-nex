//! Drag a file onto the window to check it.
//!
//! The drop is handled here, not by a command the page can call: there is no command that takes
//! a path, so the page cannot ask for a check of a file the user did not drop. (Tauri's own
//! drag-drop event does carry the dropped paths to the page, so the page does see them; it just
//! cannot send one back.) Each file is inspected by the
//! bundled engine (`the-nex --check-file`) in a child process with the user's own rights, a time
//! limit and bounded output, because a dropped file is hostile input. The engine only reads.
//! The page gets back name, verdict, score, plain reasons, size, sha256 and which checks ran.

use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{DragDropEvent, Emitter, Window, WindowEvent};
use the_nex_core::check_file::{FileCheck, Verdict};
use the_nex_core::platform;

pub const RESULT_EVENT: &str = "filecheck://result";
const MAX_FILES: usize = 20;
/// Per file. The engine's own archive check gives up after 10 s; the rest is reading.
const TIME_LIMIT: Duration = Duration::from_secs(30);
/// A real answer is well under 2 KB.
const MAX_OUTPUT: u64 = 64 * 1024;
const MAX_REASONS: usize = 8;
/// For one whole drop; files not reached by then are reported as not checked.
const TOTAL_LIMIT: Duration = Duration::from_secs(120);

static BUSY: AtomicBool = AtomicBool::new(false);

/// Clears [`BUSY`] when dropped, so a panic cannot leave every later drop refused.
struct ClearBusy;

impl Drop for ClearBusy {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

/// The one running check, or None when another is still going.
fn claim() -> Option<ClearBusy> {
    (!BUSY.swap(true, Ordering::SeqCst)).then_some(ClearBusy)
}

#[derive(Serialize, Clone)]
struct Outcome {
    results: Vec<FileCheck>,
    /// Set instead of `results` when nothing could be checked at all.
    error: Option<String>,
}

fn not_checked(file: &Path, why: &str) -> FileCheck {
    FileCheck {
        name: the_nex_core::check_file::display_name(file),
        verdict: Verdict::Refused,
        score: None,
        threshold: None,
        size: None,
        sha256: None,
        reasons: vec![why.to_string()],
        checks: Vec::new(),
    }
}

/// How one run of the engine ended.
pub enum Run {
    NotStarted,
    TooLong,
    /// Its output (at most `max_output` bytes) and whether it exited successfully.
    Done {
        ok: bool,
        output: Vec<u8>,
    },
}

/// The engine as a child that reads the same data folder as the app: the app's own, never one
/// named by a THENEX_DATA_DIR it happened to inherit (a planted model or allowed list).
fn engine_command(engine: &Path, args: &[&std::ffi::OsStr], data_dir: &Path) -> Command {
    let mut command = Command::new(engine);
    command
        .args(args)
        .env(the_nex_core::config::DATA_DIR_ENV, data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

/// Runs `engine args` as a child process with the user's own rights, no shell, no input, a time
/// limit and bounded output (shared with the startup check).
pub fn run_engine(
    engine: &Path,
    args: &[&std::ffi::OsStr],
    limit: Duration,
    max_output: u64,
) -> Run {
    let mut command = engine_command(engine, args, &crate::config().base_dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flash
    }
    let Ok(mut child) = command.spawn() else {
        return Run::NotStarted;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Run::NotStarted;
    };
    // A channel, not a join: a leftover grandchild holding the pipe must not hold us up.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.take(max_output).read_to_end(&mut out);
        let _ = sender.send(out);
    });
    let deadline = Instant::now() + limit;
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status.success()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => break None,
        }
    };
    if finished.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let output = receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    match finished {
        None => Run::TooLong,
        Some(ok) => Run::Done { ok, output },
    }
}

/// Runs the engine on one file. Never fails: anything that goes wrong is a "not checked" result.
fn check_one(engine: &Path, file: &Path, limit: Duration) -> FileCheck {
    match run_engine(
        engine,
        &["--check-file".as_ref(), file.as_os_str()],
        limit,
        MAX_OUTPUT,
    ) {
        Run::NotStarted => not_checked(
            file,
            "The Nex's protection engine could not be started, so the file was not checked.",
        ),
        Run::TooLong => not_checked(
            file,
            "Checking took too long, so it was stopped. The file was not changed.",
        ),
        Run::Done { ok, output } => {
            let line = output.split(|&b| b == b'\n').next().unwrap_or_default();
            match serde_json::from_slice::<FileCheck>(line) {
                Ok(mut result) if ok => {
                    result.reasons.truncate(MAX_REASONS);
                    result
                }
                _ => not_checked(
                    file,
                    "The check could not finish, so the file was not checked.",
                ),
            }
        }
    }
}

fn check_all(engine: &Path, paths: &[PathBuf], limit: Duration, total: Duration) -> Outcome {
    let error = if paths.is_empty() {
        Some("Nothing to check.".to_string())
    } else if paths.len() > MAX_FILES {
        Some(format!(
            "That is {} files. Drop at most {MAX_FILES} at a time.",
            paths.len()
        ))
    } else if !engine.is_file() {
        Some("The Nex's protection engine was not found next to the app, so nothing could be checked.".to_string())
    } else {
        None
    };
    Outcome {
        results: match error {
            Some(_) => Vec::new(),
            None => {
                let started = Instant::now();
                paths
                    .iter()
                    .map(|p| match total.checked_sub(started.elapsed()) {
                        Some(left) if !left.is_zero() => check_one(engine, p, limit.min(left)),
                        _ => not_checked(
                            p,
                            "This drop took too long, so this file was not checked. Drop it again on its own.",
                        ),
                    })
                    .collect()
            }
        },
        error,
    }
}

pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event else {
        return;
    };
    if window.label() != "main" || paths.is_empty() {
        return;
    }
    let window = window.clone();
    let paths = paths.clone();
    // Not on the event loop: a check can take seconds.
    std::thread::spawn(move || {
        let outcome = match claim() {
            None => Outcome {
                results: Vec::new(),
                error: Some("Still checking the last files. Try again in a moment.".into()),
            },
            Some(_clear) => {
                let engine = platform::sibling_executable(platform::DAEMON_EXE_STEM);
                check_all(&engine, &paths, TIME_LIMIT, TOTAL_LIMIT)
            }
        };
        let _ = window.emit(RESULT_EVENT, outcome);
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in engine: a script, so no real file is ever opened by these tests.
    fn fake_engine(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-fc-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("engine.sh");
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    const OK_JSON: &str = r#"{"name":"$2","verdict":"nothing_found","score":0.2,"threshold":0.65,"size":3,"sha256":"ab","reasons":[],"checks":["program"]}"#;

    #[test]
    fn the_engine_gets_exactly_two_arguments_and_no_shell() {
        // $2 is echoed back as the name; the odd file name must arrive intact, unexpanded.
        let engine = fake_engine(
            "args",
            &format!(
                "[ \"$#\" = 2 ] && [ \"$1\" = --check-file ] || exit 3\ncat <<EOF\n{OK_JSON}\nEOF"
            ),
        );
        let weird = Path::new("/tmp/a b; touch pwned `x` $(y).zip");
        let result = check_one(&engine, weird, Duration::from_secs(10));
        assert_eq!(result.verdict, Verdict::NothingFound, "{result:?}");
        assert_eq!(result.name, weird.to_str().unwrap());
        assert_eq!(result.score, Some(0.2));
    }

    #[test]
    fn a_slow_engine_is_stopped() {
        let engine = fake_engine("slow", "sleep 30");
        let started = Instant::now();
        let result = check_one(&engine, Path::new("/tmp/x.zip"), Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(result.verdict, Verdict::Refused);
        assert!(result.reasons[0].contains("too long"));
    }

    #[test]
    fn endless_or_broken_output_is_cut_off_and_not_believed() {
        for (tag, body) in [
            ("yes", "exec yes"),
            ("junk", "echo 'not json'"),
            ("fail", "echo '{}'; exit 1"),
            ("empty", "true"),
        ] {
            let engine = fake_engine(tag, body);
            let started = Instant::now();
            let result = check_one(&engine, Path::new("/tmp/x.zip"), Duration::from_secs(10));
            assert!(started.elapsed() < Duration::from_secs(8), "{tag}");
            assert_eq!(result.verdict, Verdict::Refused, "{tag}");
            assert!(result.reasons[0].contains("could not finish"), "{tag}");
        }
        let missing = check_one(
            Path::new("/nonexistent/engine"),
            Path::new("/tmp/x.zip"),
            Duration::from_secs(1),
        );
        assert!(missing.reasons[0].contains("could not be started"));
    }

    #[test]
    fn at_most_twenty_files_and_never_zero() {
        let engine = fake_engine("count", &format!("cat <<EOF\n{OK_JSON}\nEOF"));
        let many: Vec<PathBuf> = (0..=MAX_FILES)
            .map(|i| PathBuf::from(format!("/tmp/{i}")))
            .collect();
        let outcome = check_all(
            &engine,
            &many,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert!(outcome.results.is_empty());
        assert!(outcome.error.unwrap().contains("at most 20"));
        assert!(check_all(
            &engine,
            &[],
            Duration::from_secs(5),
            Duration::from_secs(60)
        )
        .error
        .is_some());
        let twenty = check_all(
            &engine,
            &many[..MAX_FILES],
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert_eq!((twenty.results.len(), twenty.error), (20, None));
        let no_engine = check_all(
            Path::new("/nonexistent/engine"),
            &many[..1],
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert!(no_engine.error.unwrap().contains("not found"));
    }

    #[test]
    fn the_result_carries_only_the_allowed_fields() {
        let json =
            serde_json::to_value(not_checked(Path::new("/secret/folder/a.zip"), "why")).unwrap();
        assert_eq!(json["name"], "a.zip");
        assert!(!json.to_string().contains("secret"));
    }

    #[test]
    fn a_drop_that_runs_out_of_total_time_reports_the_rest_as_not_checked() {
        let engine = fake_engine("total", "sleep 30");
        let files: Vec<PathBuf> = (0..3)
            .map(|i| PathBuf::from(format!("/tmp/{i}.zip")))
            .collect();
        let started = Instant::now();
        let outcome = check_all(
            &engine,
            &files,
            Duration::from_secs(10),
            Duration::from_millis(400),
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome.results.len(), 3);
        assert!(outcome.results[0].reasons[0].contains("too long"));
        for rest in &outcome.results[1..] {
            assert_eq!(rest.verdict, Verdict::Refused);
            assert!(rest.reasons[0].contains("drop took too long"), "{rest:?}");
        }
    }

    #[test]
    fn the_engine_child_is_pointed_at_the_apps_own_data_folder() {
        let engine = fake_engine("env", "echo \"$THENEX_DATA_DIR\"");
        let mut command = engine_command(&engine, &[], Path::new("/the/apps/own"));
        let out = command.output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "/the/apps/own");
    }

    #[test]
    fn busy_is_cleared_even_when_the_check_panics() {
        // One test, because BUSY is shared: a second drop is refused while the first runs.
        let first = claim();
        assert!(first.is_some() && claim().is_none());
        drop(first);
        assert!(claim().is_some() && !BUSY.load(Ordering::SeqCst));
        BUSY.store(true, Ordering::SeqCst);
        let result = std::panic::catch_unwind(|| {
            let _clear = ClearBusy;
            panic!("check blew up");
        });
        assert!(result.is_err());
        assert!(!BUSY.load(Ordering::SeqCst));
    }
}
