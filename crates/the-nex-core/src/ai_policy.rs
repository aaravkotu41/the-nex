//! Hard guardrails for the binary AI. `decide` runs after the model scored a file and before
//! anything happens to it. It is a closed function: no flags, no settings, no environment can
//! widen what it allows; configuration can only make the AI stricter (higher threshold).
//!
//! Rules, in order:
//!  1. A score that is NaN or below the effective threshold never causes anything.
//!  2. The effective threshold is clamped to [MIN_THRESHOLD, MAX_THRESHOLD] (NaN -> default).
//!  3. Validly signed / OS-trusted binaries are never acted on.
//!  4. Symlinks, paths with `..`, OS-critical paths, and The Nex's own files and data are
//!     alert-only.
//!  5. The AI never deletes: the strongest file action is quarantine (a reversible move).
//!  6. Stopping a running program needs a new process (not already running when protection
//!     started) and a score of at least KILL_CONFIDENCE.
//!  7. Dry-run always wins: the action is reported, never performed.
//!  8. Every action carries a non-empty explanation, else it is downgraded to an alert.

use std::path::{Path, PathBuf};

pub const MIN_THRESHOLD: f32 = 0.5;
pub const MAX_THRESHOLD: f32 = 0.99;
pub const DEFAULT_THRESHOLD: f32 = 0.65;
/// Score needed to stop a running program (cannot be undone).
pub const KILL_CONFIDENCE: f32 = 0.9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A file on disk that is not currently executing.
    File,
    /// The image of a running process; `preexisting` = already running at protection start.
    Process { preexisting: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Ignore,
    Alert(&'static str),
    Quarantine,
    TerminateAndQuarantine,
    WouldQuarantine,
    WouldTerminateAndQuarantine,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub path: &'a Path,
    pub score: f32,
    pub threshold: f32,
    pub trusted: bool,
    pub dry_run: bool,
    pub target: Target,
    pub explanation: &'a str,
    /// The Nex's data directory (settings, quarantine, logs).
    pub data_dir: &'a Path,
}

/// Threshold actually used, whatever the configuration says.
pub fn effective_threshold(configured: f32) -> f32 {
    if configured.is_nan() {
        DEFAULT_THRESHOLD
    } else {
        configured.clamp(MIN_THRESHOLD, MAX_THRESHOLD)
    }
}

fn norm(path: &Path) -> String {
    let drive = std::env::var("SystemDrive")
        .unwrap_or_default()
        .to_lowercase();
    norm_on(path, if drive.len() == 2 { &drive } else { "c:" })
}

/// `system_drive` ("c:") is stripped so OS roots compare drive-less; any other drive keeps its
/// prefix and therefore never matches an OS path (D:\Windows\System32 is not the OS).
fn norm_on(path: &Path, system_drive: &str) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/").to_lowercase();
    // Win32 extended/device/NT prefixes: \\?\C:\x, \\?\UNC\h\s, \\.\C:\x, \??\C:\x
    if let Some(rest) = s.strip_prefix("//?/unc/") {
        s = format!("//{rest}");
    } else if let Some(rest) = ["//?/", "//./", "/??/"]
        .iter()
        .find_map(|p| s.strip_prefix(p))
    {
        s = rest.to_string();
    }
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && s.starts_with(system_drive) {
        s.drain(..2); // system drive letter
        if !s.starts_with('/') {
            s.insert(0, '/');
        }
    }
    // macOS firmlink: /System/Volumes/Data/Users/x is /Users/x, not an OS path.
    const DATA_VOLUME: &str = "/system/volumes/data";
    if within(&s, DATA_VOLUME) {
        s.drain(..DATA_VOLUME.len());
        if s.is_empty() {
            s.push('/');
        }
    }
    for prefix in ["/private/tmp", "/private/var", "/private/etc"] {
        if s == prefix || s.starts_with(&format!("{prefix}/")) {
            s.drain(..8);
            break;
        }
    }
    s
}

fn within(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

const CRITICAL_ROOTS: &[&str] = &[
    "/system",
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/library/apple",
    "/program files/windowsapps",
];

/// Windows OS trees, minus the subfolders ordinary users can write to. A blanket `/windows` rule
/// made malware dropped in C:\Windows\Tasks or \Temp alert-only; the signature check cannot
/// replace the path rule here because it sees only embedded signatures, while most OS binaries
/// are catalog-signed and would look unsigned.
const WINDOWS_OS_ROOTS: &[&str] = &["/windows/system32", "/windows/syswow64", "/windows/winsxs"];
const WINDOWS_USER_WRITABLE: &[&str] = &[
    "tasks",
    "temp",
    "tracing",
    "fxstmp",
    "debug",
    "com/dmp",
    "spool/drivers/color",
    "spool/printers",
    "registration/crmlog",
    "microsoft/crypto/rsa/machinekeys",
    "logfiles",
];

fn is_windows_os_path(p: &str) -> bool {
    WINDOWS_OS_ROOTS.iter().any(|root| {
        within(p, root)
            && !WINDOWS_USER_WRITABLE
                .iter()
                .any(|w| within(p, &format!("{root}/{w}")))
    })
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

fn own_paths() -> Vec<PathBuf> {
    let mut own = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_lowercase();
                    if name.starts_with("the-nex") || name.starts_with("thenex") {
                        own.push(e.path());
                    }
                }
            }
        }
        own.push(exe);
    }
    own
}

/// OS-critical paths and The Nex's own binaries (and, via `is_own_data`, its data directory).
pub fn is_os_critical_path(path: &Path) -> bool {
    if has_parent_component(path) {
        return true; // cannot be verified lexically
    }
    let p = norm(path);
    CRITICAL_ROOTS.iter().any(|r| within(&p, r))
        || is_windows_os_path(&p)
        || own_paths().iter().any(|o| norm(o) == p)
}

fn is_own_data(path: &Path, data_dir: &Path) -> bool {
    within(&norm(path), &norm(data_dir))
}

/// The one decision point. Pure apart from reading the daemon's own executable location.
pub fn decide(req: &Request<'_>) -> Action {
    let threshold = effective_threshold(req.threshold);
    if req.score.is_nan() || req.score < threshold {
        return Action::Ignore;
    }
    if req.trusted {
        return Action::Ignore;
    }
    if is_os_critical_path(req.path) || is_own_data(req.path, req.data_dir) {
        return Action::Alert("protected location or The Nex's own file; alert only");
    }
    if std::fs::symlink_metadata(req.path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Action::Alert("symbolic link; alert only");
    }
    if req.explanation.trim().is_empty() {
        return Action::Alert("no explanation available; alert only");
    }
    match req.target {
        Target::File => {
            if req.dry_run {
                Action::WouldQuarantine
            } else {
                Action::Quarantine
            }
        }
        Target::Process { preexisting: true } => {
            Action::Alert("already running when protection started")
        }
        Target::Process { preexisting: false } if req.score < threshold.max(KILL_CONFIDENCE) => {
            Action::Alert("below the confidence needed to stop a running program")
        }
        Target::Process { preexisting: false } => {
            if req.dry_run {
                Action::WouldTerminateAndQuarantine
            } else {
                Action::TerminateAndQuarantine
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(path: &'a Path, score: f32, target: Target) -> Request<'a> {
        Request {
            path,
            score,
            threshold: 0.65,
            trusted: false,
            dry_run: false,
            target,
            explanation: "score=0.99; packed",
            data_dir: Path::new("/nonexistent/thenex-data"),
        }
    }

    #[test]
    fn only_the_system_drive_loses_its_letter() {
        let evil = Path::new("D:\\Windows\\System32\\evil.exe");
        assert_eq!(norm_on(evil, "c:"), "d:/windows/system32/evil.exe");
        assert!(!is_windows_os_path(&norm_on(evil, "c:")));
        // the same path is the OS when D: really is the system drive
        assert_eq!(norm_on(evil, "d:"), "/windows/system32/evil.exe");
        assert!(is_windows_os_path(&norm_on(evil, "d:")));
        assert_eq!(
            norm_on(Path::new("C:\\Windows\\x.exe"), "c:"),
            "/windows/x.exe"
        );
    }

    #[test]
    fn threshold_is_clamped_whatever_the_config_says() {
        for hostile in [0.0, -5.0, 0.01, f32::NEG_INFINITY] {
            assert_eq!(effective_threshold(hostile), MIN_THRESHOLD);
        }
        assert_eq!(effective_threshold(f32::NAN), DEFAULT_THRESHOLD);
        assert_eq!(effective_threshold(7.0), MAX_THRESHOLD);
        let p = Path::new("/tmp/x/evil");
        let mut r = req(p, 0.4, Target::File);
        r.threshold = 0.0;
        assert_eq!(
            decide(&r),
            Action::Ignore,
            "0.4 must never act, even at threshold 0"
        );
        r.score = 0.5;
        assert_eq!(decide(&r), Action::Quarantine);
    }

    #[test]
    fn low_or_nan_scores_never_act() {
        let p = Path::new("/tmp/x/evil");
        for s in [f32::NAN, 0.0, 0.64, -1.0] {
            assert_eq!(decide(&req(p, s, Target::File)), Action::Ignore);
        }
    }

    #[test]
    fn signed_binaries_are_never_touched() {
        let p = Path::new("/tmp/x/evil");
        let mut r = req(p, 1.0, Target::Process { preexisting: false });
        r.trusted = true;
        assert_eq!(decide(&r), Action::Ignore);
    }

    #[test]
    fn os_critical_and_own_paths_are_alert_only() {
        for p in [
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/usr/bin/ssh",
            "/sbin/launchd",
            "C:\\Windows\\System32\\cmd.exe",
            "c:/WINDOWS/syswow64/x.exe",
            "/tmp/../System/x",
            "\\\\?\\C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\WinSxS\\x\\y.dll",
            "/System/Volumes/Data/System/Library/x",
        ] {
            let path = Path::new(p);
            for target in [Target::File, Target::Process { preexisting: false }] {
                assert!(
                    matches!(decide(&req(path, 1.0, target)), Action::Alert(_)),
                    "{p}"
                );
            }
        }
        let own = std::env::current_exe().unwrap();
        assert!(matches!(
            decide(&req(&own, 1.0, Target::File)),
            Action::Alert(_)
        ));
        let mut r = req(
            Path::new("/data/TheNex/Quarantine/a.bin"),
            1.0,
            Target::File,
        );
        r.data_dir = Path::new("/data/thenex");
        assert!(matches!(decide(&r), Action::Alert(_)));
    }

    #[test]
    fn lookalike_and_user_writable_paths_are_actionable() {
        for p in [
            "/Users/x/Downloads/X.app/Contents/MacOS/the-nexus",
            "/Users/x/Downloads/TheNex.app/Contents/MacOS/thenex-evil",
            "/Applications/TheNex.app.evil/x",
            "/System/Volumes/Data/Users/x/Downloads/evil",
            "C:\\Windows\\Tasks\\evil.exe",
            "C:\\Windows\\Temp\\evil.exe",
            "C:\\Windows\\System32\\spool\\drivers\\color\\evil.exe",
            "\\\\?\\C:\\Windows\\Temp\\evil.exe",
            "\\\\?\\UNC\\host\\share\\evil.exe",
        ] {
            assert_eq!(
                decide(&req(Path::new(p), 1.0, Target::File)),
                Action::Quarantine,
                "{p}"
            );
        }
    }

    #[test]
    fn dry_run_always_wins() {
        let p = Path::new("/tmp/x/evil");
        for target in [Target::File, Target::Process { preexisting: false }] {
            let mut r = req(p, 1.0, target);
            r.dry_run = true;
            assert!(matches!(
                decide(&r),
                Action::WouldQuarantine | Action::WouldTerminateAndQuarantine
            ));
        }
    }

    #[test]
    fn running_programs_need_new_process_and_high_confidence() {
        let p = Path::new("/tmp/x/evil");
        assert!(matches!(
            decide(&req(p, 1.0, Target::Process { preexisting: true })),
            Action::Alert(_)
        ));
        assert!(matches!(
            decide(&req(p, 0.8, Target::Process { preexisting: false })),
            Action::Alert(_)
        ));
        assert_eq!(
            decide(&req(p, 0.95, Target::Process { preexisting: false })),
            Action::TerminateAndQuarantine
        );
        let mut r = req(p, 0.95, Target::Process { preexisting: false });
        r.threshold = 5.0; // clamped to 0.99, so 0.95 is below it
        assert_eq!(decide(&r), Action::Ignore);
    }

    #[test]
    fn every_action_needs_an_explanation() {
        let p = Path::new("/tmp/x/evil");
        let mut r = req(p, 1.0, Target::File);
        r.explanation = "  ";
        assert!(matches!(decide(&r), Action::Alert(_)));
    }

    #[test]
    fn symlinks_are_alert_only() {
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("thenex-pol-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let link = dir.join("link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink("/etc/hosts", &link).unwrap();
            assert!(matches!(
                decide(&req(&link, 1.0, Target::File)),
                Action::Alert(_)
            ));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
