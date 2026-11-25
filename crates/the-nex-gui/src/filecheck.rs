//! Drag a file onto the window to check it.
//!
//! The drop is handled here, not by a command the page can call: the page never supplies a path,
//! so it cannot use this to look at files the user did not drop. Each file is inspected by the
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

static BUSY: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Clone)]
struct Outcome {
    results: Vec<FileCheck>,
    /// Set instead of `results` when nothing could be checked at all.
    error: Option<String>,
}

fn not_checked(file: &Path, why: &str) -> FileCheck {
    FileCheck {
        name: file
            .file_name()
            .unwrap_or(file.as_os_str())
            .to_string_lossy()
            .chars()
            .take(200)
            .collect(),
        verdict: Verdict::Refused,
        score: None,
        threshold: None,
        size: None,
        sha256: None,
        reasons: vec![why.to_string()],
        checks: Vec::new(),
    }
}

/// Runs the engine on one file. Never fails: anything that goes wrong is a "not checked" result.
fn check_one(engine: &Path, file: &Path, limit: Duration) -> FileCheck {
    let mut command = Command::new(engine);
    command
        .arg("--check-file")
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flash
    }
    let Ok(mut child) = command.spawn() else {
        return not_checked(
            file,
            "The Nex's protection engine could not be started, so the file was not checked.",
        );
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return not_checked(file, "The check could not be started.");
    };
    // A channel, not a join: a leftover grandchild holding the pipe must not hold us up.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.take(MAX_OUTPUT).read_to_end(&mut out);
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
    if finished.is_none() {
        return not_checked(
            file,
            "Checking took too long, so it was stopped. The file was not changed.",
        );
    }
    let line = output.split(|&b| b == b'\n').next().unwrap_or_default();
    match serde_json::from_slice::<FileCheck>(line) {
        Ok(mut result) if finished == Some(true) => {
            result.reasons.truncate(MAX_REASONS);
            result
        }
        _ => not_checked(
            file,
            "The check could not finish, so the file was not checked.",
        ),
    }
}

fn check_all(engine: &Path, paths: &[PathBuf], limit: Duration) -> Outcome {
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
            None => paths.iter().map(|p| check_one(engine, p, limit)).collect(),
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
        let outcome = if BUSY.swap(true, Ordering::SeqCst) {
            Outcome {
                results: Vec::new(),
                error: Some("Still checking the last files. Try again in a moment.".into()),
            }
        } else {
            let engine = platform::sibling_executable(platform::DAEMON_EXE_STEM);
            let outcome = check_all(&engine, &paths, TIME_LIMIT);
            BUSY.store(false, Ordering::SeqCst);
            outcome
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
        let outcome = check_all(&engine, &many, Duration::from_secs(5));
        assert!(outcome.results.is_empty());
        assert!(outcome.error.unwrap().contains("at most 20"));
        assert!(check_all(&engine, &[], Duration::from_secs(5))
            .error
            .is_some());
        let twenty = check_all(&engine, &many[..MAX_FILES], Duration::from_secs(5));
        assert_eq!((twenty.results.len(), twenty.error), (20, None));
        let no_engine = check_all(
            Path::new("/nonexistent/engine"),
            &many[..1],
            Duration::from_secs(5),
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
}
