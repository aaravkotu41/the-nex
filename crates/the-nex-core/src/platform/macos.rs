use crate::canary;
use crate::config::{self, AppConfig};
use crate::logger;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub const SELF_EXE_NAME: &str = "the-nex";
const DAEMON_LABEL: &str = "com.thenex.edr";
const AGENT_LABEL: &str = "com.thenex.edr.notifier";
const DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.thenex.edr.plist";
const AGENT_PLIST: &str = "/Library/LaunchAgents/com.thenex.edr.notifier.plist";
const NOTIFIER_ARG: &str = "--notifier";
const LAUNCHCTL: &str = "/bin/launchctl";
const BOOTSTRAP_ATTEMPTS: u32 = 3;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

const USERS_ROOT: &str = "/Users";
const SKIPPED_HOMES: &[&str] = &["shared"];

/// SIP-protected locations; /usr/local is deliberately excluded.
const TRUSTED_ROOTS: &[&str] = &[
    "/System/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
];

const NOTIFY_SCRIPT: &str =
    "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run\n";

/// Runs argv (program first) as root after the standard macOS administrator prompt.
const ELEVATE_SCRIPT: &str = "on run argv\n\
set cmd to \"\"\n\
repeat with a in argv\n\
set cmd to cmd & quoted form of (a as text) & \" \"\n\
end repeat\n\
do shell script cmd with administrator privileges\n\
end run\n";

extern "C" {
    fn geteuid() -> u32;
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { geteuid() == 0 }
}

fn require_root() -> Result<(), String> {
    if is_root() {
        Ok(())
    } else {
        Err("administrator rights required; re-run with sudo".to_string())
    }
}

/// Lower-cased, trailing-slash-free key; /private/{tmp,var,etc} folded onto their /tmp-style
/// aliases because FSEvents reports the resolved form.
pub fn path_key(path: &Path) -> String {
    let mut key = path.to_string_lossy().to_lowercase();
    for prefix in ["/private/tmp", "/private/var", "/private/etc"] {
        if key == prefix || key.starts_with(&format!("{prefix}/")) {
            key = key["/private".len()..].to_string();
            break;
        }
    }
    while key.len() > 1 && key.ends_with('/') {
        key.pop();
    }
    key
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path_key(path);
    let root = path_key(root);
    if path == root {
        return true;
    }
    let prefix = if root.ends_with('/') {
        root
    } else {
        format!("{root}/")
    };
    path.starts_with(&prefix)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .filter(|p| seen.insert(path_key(p)))
        .collect()
}

/// Real home folders under /Users (Shared, dot-entries and symlinks skipped).
fn user_homes() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(USERS_ROOT) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            let name = entry.file_name().to_string_lossy().to_lowercase();
            kind.is_dir()
                && !kind.is_symlink()
                && !name.starts_with('.')
                && !SKIPPED_HOMES.contains(&name.as_str())
        })
        .map(|entry| entry.path())
        .collect()
}

fn home_folders(names: &[&str]) -> Vec<PathBuf> {
    user_homes()
        .iter()
        .flat_map(|home| names.iter().map(move |name| home.join(name)))
        .filter(|p| p.is_dir())
        .collect()
}

pub fn discover_watched_dirs() -> Vec<PathBuf> {
    let mut dirs = home_folders(&["Downloads", "Desktop"]);
    let tmp = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    if tmp.is_dir() {
        dirs.push(tmp);
    }
    dedup_paths(dirs)
}

pub fn discover_canary_dirs() -> Vec<PathBuf> {
    dedup_paths(home_folders(&["Desktop", "Documents"]))
}

/// Downloads and Desktop of every real user (/tmp is left to the live watcher).
pub fn discover_quick_scan_dirs() -> Vec<PathBuf> {
    dedup_paths(home_folders(&["Downloads", "Desktop"]))
}

pub fn set_hidden_file(path: &Path) {
    let _ = run_tool(
        Path::new("/usr/bin/chflags"),
        [OsStr::new("hidden"), path.as_os_str()],
    );
}

pub fn lock_quarantined_file(path: &Path) {
    if let Err(e) = fs::set_permissions(path, Permissions::from_mode(0o000)) {
        logger::warn(format!("could not lock {}: {e}", path.display()));
    }
}

pub fn unlock_restored_file(path: &Path) {
    if let Err(e) = fs::set_permissions(path, Permissions::from_mode(0o644)) {
        logger::warn(format!("could not unlock {}: {e}", path.display()));
    }
}

fn osascript_notification(title: &str, body: &str) -> io::Result<()> {
    // Script on stdin, text as argv: no AppleScript escaping and no `osascript -e` on the cmdline.
    let mut child = Command::new("/usr/bin/osascript")
        .arg("-")
        .arg(title)
        .arg(body)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(NOTIFY_SCRIPT.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("osascript exited with {status}")))
    }
}

pub fn send_desktop_notification(title: &str, body: &str) {
    let primary = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .show()
        .map(|_| ());
    if let Err(primary) = primary {
        if let Err(fallback) = osascript_notification(title, body) {
            logger::warn(format!(
                "desktop notification failed (notify-rust: {primary}; osascript: {fallback})"
            ));
        }
    }
}

fn has_apple_anchored_signature(path: &Path) -> bool {
    Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R=anchor apple generic"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// SIP-protected system paths, or a valid signature chaining to Apple (Apple / Developer ID).
pub fn is_trusted_binary(path: &Path) -> bool {
    let text = path.to_string_lossy();
    TRUSTED_ROOTS.iter().any(|root| text.starts_with(root)) || has_apple_anchored_signature(path)
}

fn run_tool<I, S>(program: &Path, args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.is_empty() {
        message = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    Err(format!(
        "{} failed ({}): {message}",
        program.display(),
        output.status
    ))
}

fn launchctl<I, S>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_tool(Path::new(LAUNCHCTL), args)
}

/// A fresh bootout can leave the label briefly registered; retry the bootstrap.
fn bootstrap(domain: &str, plist: &str) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..BOOTSTRAP_ATTEMPTS {
        match launchctl(["bootstrap", domain, plist]) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        if attempt + 1 < BOOTSTRAP_ATTEMPTS {
            thread::sleep(Duration::from_secs(1));
        }
    }
    Err(last)
}

fn console_uid() -> Option<u32> {
    fs::metadata("/dev/console")
        .ok()
        .map(|m| m.uid())
        .filter(|uid| *uid != 0)
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn plist_document(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n{body}</dict>\n</plist>\n"
    )
}

fn daemon_plist(exe: &Path, cfg: &AppConfig) -> String {
    let stderr_log = cfg.log_dir.join("daemon.err.log");
    plist_document(&format!(
        "  <key>Label</key>\n  <string>{DAEMON_LABEL}</string>\n\
  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n  </array>\n\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <true/>\n\
  <key>ThrottleInterval</key>\n  <integer>5</integer>\n\
  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
        xml_escape(&exe.to_string_lossy()),
        xml_escape(&stderr_log.to_string_lossy())
    ))
}

fn agent_plist(exe: &Path) -> String {
    plist_document(&format!(
        "  <key>Label</key>\n  <string>{AGENT_LABEL}</string>\n\
  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>{NOTIFIER_ARG}</string>\n  </array>\n\
  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <true/>\n\
  <key>ThrottleInterval</key>\n  <integer>10</integer>\n",
        xml_escape(&exe.to_string_lossy())
    ))
}

/// launchd rejects job files that are not root-owned and 0644.
fn write_job_file(path: &str, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("cannot write {path}: {e}"))?;
    fs::set_permissions(path, Permissions::from_mode(0o644))
        .map_err(|e| format!("cannot set permissions on {path}: {e}"))
}

fn harden_data_dirs(cfg: &AppConfig) -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = cfg.ensure_dirs() {
        notes.push(e);
    }
    for (dir, mode) in [
        (&cfg.base_dir, 0o755),
        (&cfg.log_dir, 0o755),
        (&cfg.quarantine_dir, 0o700),
    ] {
        if let Err(e) = fs::set_permissions(dir, Permissions::from_mode(mode)) {
            notes.push(format!("cannot set permissions on {}: {e}", dir.display()));
        }
    }
    notes
}

fn notifier_processes(sys: &System) -> Vec<(sysinfo::Pid, Option<u32>)> {
    let me = std::process::id();
    sys.processes()
        .values()
        .filter(|p| {
            p.pid().as_u32() != me
                && OsStr::new(p.name()).to_string_lossy() == SELF_EXE_NAME
                && p.cmd()
                    .iter()
                    .any(|arg| OsStr::new(arg).to_string_lossy() == NOTIFIER_ARG)
        })
        .map(|p| (p.pid(), p.user_id().map(|uid| **uid)))
        .collect()
}

fn process_snapshot() -> System {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
    sys
}

pub fn install_service() -> Result<String, String> {
    require_root()?;
    let exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("cannot resolve executable path: {e}"))?;
    if exe.starts_with("/Volumes") {
        return Err(
            "running from a mounted disk image; copy TheNex.app to /Applications and install from there"
                .to_string(),
        );
    }

    let cfg = AppConfig::for_base_dir(&config::default_base_dir());
    let mut notes = harden_data_dirs(&cfg);
    write_job_file(DAEMON_PLIST, &daemon_plist(&exe, &cfg))?;
    write_job_file(AGENT_PLIST, &agent_plist(&exe))?;
    notes.push(format!("wrote {DAEMON_PLIST} and {AGENT_PLIST}"));

    let daemon_target = format!("system/{DAEMON_LABEL}");
    let _ = launchctl(["bootout", daemon_target.as_str()]);
    let _ = launchctl(["enable", daemon_target.as_str()]);
    bootstrap("system", DAEMON_PLIST).map_err(|e| format!("cannot load the daemon: {e}"))?;
    notes.push(format!(
        "daemon '{DAEMON_LABEL}' loaded (RunAtLoad, KeepAlive)"
    ));

    match console_uid() {
        Some(uid) => {
            let domain = format!("gui/{uid}");
            let _ = launchctl(["bootout", format!("{domain}/{AGENT_LABEL}").as_str()]);
            match bootstrap(&domain, AGENT_PLIST) {
                Ok(()) => notes.push(format!("notifier loaded for console user {uid}")),
                Err(e) => notes.push(format!("notifier starts at next login ({e})")),
            }
        }
        None => notes.push("notifier starts at next login".to_string()),
    }
    notes.push(format!("executable: {}", exe.display()));
    notes.push(
        "Grant Full Disk Access to this executable (System Settings > Privacy & Security > Full Disk Access) so Desktop, Documents and Downloads can be protected"
            .to_string(),
    );
    Ok(notes.join("\n"))
}

pub fn uninstall_service() -> Result<String, String> {
    require_root()?;
    let mut notes = Vec::new();

    let sys = process_snapshot();
    let mut uids: BTreeSet<u32> = notifier_processes(&sys)
        .iter()
        .filter_map(|(_, uid)| *uid)
        .collect();
    uids.extend(console_uid());
    for uid in uids {
        let _ = launchctl(["bootout", format!("gui/{uid}/{AGENT_LABEL}").as_str()]);
    }

    match launchctl(["bootout", format!("system/{DAEMON_LABEL}").as_str()]) {
        Ok(()) => notes.push(format!("daemon '{DAEMON_LABEL}' stopped")),
        Err(_) => notes.push(format!("daemon '{DAEMON_LABEL}' was not loaded")),
    }
    for plist in [DAEMON_PLIST, AGENT_PLIST] {
        match fs::remove_file(plist) {
            Ok(()) => notes.push(format!("removed {plist}")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => notes.push(format!("cannot remove {plist}: {e}")),
        }
    }

    let sys = process_snapshot();
    let stopped = notifier_processes(&sys)
        .iter()
        .filter(|(pid, _)| sys.process(*pid).is_some_and(|p| p.kill()))
        .count();
    if stopped > 0 {
        notes.push(format!("stopped {stopped} notifier process(es)"));
    }
    let removed = canary::remove_canaries(&discover_canary_dirs());
    notes.push(format!("removed {removed} canary file(s)"));
    Ok(notes.join("\n"))
}

static SHUTDOWN_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

extern "C" fn on_shutdown_signal(_signum: i32) {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

fn install_signal_handlers(shutdown: Arc<AtomicBool>) {
    let _ = SHUTDOWN_FLAG.set(shutdown);
    // SAFETY: the handler only performs an atomic load and store.
    unsafe {
        signal(SIGINT, on_shutdown_signal);
        signal(SIGTERM, on_shutdown_signal);
        signal(SIGHUP, on_shutdown_signal);
    }
}

/// Runs the engine as the launchd daemon; returns when launchd sends SIGTERM.
pub fn run_service(shutdown: Arc<AtomicBool>, cfg: AppConfig) -> Result<(), String> {
    if !is_root() {
        return Err(
            "the daemon runs as root under launchd; install it with sudo Contents/Resources/install_mac.sh, or use --console to run interactively"
                .to_string(),
        );
    }
    install_signal_handlers(Arc::clone(&shutdown));
    crate::engine::run(cfg, shutdown);
    Ok(())
}

pub fn install_ctrlc_handler(shutdown: Arc<AtomicBool>) {
    install_signal_handlers(shutdown);
}

/// LaunchAgents run without a terminal, so there is nothing to detach.
pub fn detach_console() {}

pub fn service_installed() -> bool {
    Path::new(DAEMON_PLIST).is_file()
}

/// The menu-bar notifier is the LaunchAgent; the tray icon is a Windows feature.
pub fn tray_is_running() -> bool {
    false
}

pub fn run_tray(_cfg: AppConfig) -> Result<(), String> {
    Err(
        "--tray is available on Windows; on macOS notifications come from the notifier LaunchAgent"
            .to_string(),
    )
}

/// Runs `program args` as root via the standard administrator prompt; returns its exit code.
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<i32, String> {
    if is_root() {
        return Command::new(program)
            .args(args)
            .status()
            .map(|s| s.code().unwrap_or(-1))
            .map_err(|e| format!("{}: {e}", program.display()));
    }
    let mut child = Command::new("/usr/bin/osascript")
        .arg("-")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("osascript: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ELEVATE_SCRIPT.as_bytes())
            .map_err(|e| format!("osascript: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("osascript: {e}"))?;
    if output.status.success() {
        return Ok(0);
    }
    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.contains("-128") {
        Err("the administrator prompt was cancelled".to_string())
    } else {
        Err(format!("{} failed: {message}", program.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_is_windows_only() {
        assert!(!tray_is_running());
        let cfg = AppConfig::for_base_dir(&env::temp_dir().join("thenex-tray-mac"));
        assert!(run_tray(cfg).is_err());
        assert!(ELEVATE_SCRIPT.contains("with administrator privileges"));
        assert!(!ELEVATE_SCRIPT.contains("osascript -e"));
    }

    #[test]
    fn path_keys_normalize() {
        assert_eq!(path_key(Path::new("/Users/A/")), "/users/a");
        assert_eq!(path_key(Path::new("/private/tmp/x")), "/tmp/x");
        assert!(path_is_within(
            Path::new("/private/tmp/sandbox/a"),
            Path::new("/tmp/sandbox")
        ));
        assert!(!path_is_within(
            Path::new("/Users/Ab/x"),
            Path::new("/Users/A")
        ));
    }

    #[test]
    fn system_binaries_are_trusted() {
        assert!(is_trusted_binary(Path::new("/bin/ls")));
        assert!(!is_trusted_binary(Path::new(
            "/usr/local/bin/definitely-missing"
        )));
    }

    #[test]
    fn lock_and_unlock_change_mode() {
        let path = env::temp_dir().join(format!("thenex-mode-{}", std::process::id()));
        fs::write(&path, b"x").unwrap();
        lock_quarantined_file(&path);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o000
        );
        unlock_restored_file(&path);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn job_files_are_well_formed() {
        let cfg = AppConfig::for_base_dir(Path::new("/Library/Application Support/TheNex"));
        let exe = Path::new("/Applications/TheNex.app/Contents/MacOS/the-nex");
        let daemon = daemon_plist(exe, &cfg);
        assert!(daemon.contains("<string>com.thenex.edr</string>"));
        assert!(daemon.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(daemon.contains("<key>RunAtLoad</key>\n  <true/>"));
        let agent = agent_plist(exe);
        assert!(agent.contains("<string>--notifier</string>"));
        assert!(agent.contains("<string>Aqua</string>"));
        assert_eq!(xml_escape("a&b<c>"), "a&amp;b&lt;c&gt;");
    }
}
