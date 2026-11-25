use crate::canary;
use crate::config::{self, AppConfig};
use crate::known_bad;
use crate::logger;
use crate::quarantine;
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

/// Runs argv (program first) as root after the standard macOS administrator prompt, which
/// shows the environment variable `PROMPT_ENV` as its message. The command arrives via argv and
/// nothing is interpolated into the script. The message stays out of the command line on
/// purpose: it can hold a file name that someone else chose, and a command line is what the
/// living-off-the-land rules read (a file called "hidden answer" would get our own prompt
/// process killed as a password phisher).
const ELEVATE_SCRIPT: &str = "on run argv\n\
set cmd to \"\"\n\
repeat with i from 1 to count of argv\n\
set cmd to cmd & quoted form of (item i of argv as text) & \" \"\n\
end repeat\n\
do shell script cmd with prompt (system attribute \"THENEX_PROMPT\") with administrator privileges\n\
end run\n";
const PROMPT_ENV: &str = "THENEX_PROMPT";

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
    if super::has_parent_dir(path) {
        return false;
    }
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
    folders_in(&user_homes(), names)
}

/// Real folders only: a Downloads or Desktop that is a link (to anywhere, by anyone with write
/// access to that home) is never scanned or watched, as root would follow it out of the home.
fn folders_in(homes: &[PathBuf], names: &[&str]) -> Vec<PathBuf> {
    homes
        .iter()
        .flat_map(|home| names.iter().map(move |name| home.join(name)))
        .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
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
    // A Desktop/Documents that is itself a symlink is never a canary site (root would write through it).
    dedup_paths(
        home_folders(&["Desktop", "Documents"])
            .into_iter()
            .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
            .collect(),
    )
}

/// Downloads and Desktop of every real user (/tmp is left to the live watcher).
pub fn discover_quick_scan_dirs() -> Vec<PathBuf> {
    dedup_paths(home_folders(&["Downloads", "Desktop"]))
}

pub fn set_hidden_file(path: &Path) {
    let _ = run_tool(
        Path::new("/usr/bin/chflags"),
        [OsStr::new("-h"), OsStr::new("hidden"), path.as_os_str()],
    );
}

pub fn lock_quarantined_file(path: &Path) {
    // fchmod on an O_NOFOLLOW handle: a planted symlink is refused, never chmod'd through.
    if let Err(e) = quarantine::chmod_nofollow(path, |_| 0o000) {
        logger::warn(format!("could not lock {}: {e}", path.display()));
    }
}

pub fn unlock_restored_file(path: &Path) {
    if let Err(e) = quarantine::chmod_nofollow(path, |_| 0o644) {
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
    // Without this the library looks up an app named "use_default", and macOS answers with a
    // "Where is use_default?" Choose Application window.
    static APP_SET: std::sync::Once = std::sync::Once::new();
    APP_SET.call_once(|| {
        let _ = notify_rust::set_application("com.thenex.edr");
    });
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

fn satisfies_requirement(path: &Path, requirement: &str) -> bool {
    Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", requirement])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn has_apple_anchored_signature(path: &Path) -> bool {
    satisfies_requirement(path, "-R=anchor apple generic")
}

/// Signed by Apple itself (macOS and Apple's own apps), not merely by a Developer ID.
pub fn is_os_vendor_signed(path: &Path) -> bool {
    satisfies_requirement(path, "-R=anchor apple")
}

/// Whether `vendor` ("Apple" or "Microsoft") itself signed it.
pub fn is_signed_by(path: &Path, vendor: &str) -> Option<bool> {
    Some(match vendor {
        "Apple" => is_os_vendor_signed(path),
        "Microsoft" => satisfies_requirement(path, SIGNED_BY_MICROSOFT),
        _ => false,
    })
}

/// A Developer ID of Microsoft's own team: any other maker's must not do.
const SIGNED_BY_MICROSOFT: &str =
    "-R=anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9";

/// SIP-protected system paths, or a valid signature chaining to Apple (Apple / Developer ID).
pub fn is_trusted_binary(path: &Path) -> bool {
    in_trusted_root(path) || has_apple_anchored_signature(path)
}

/// Lexical SIP-root check. The Data volume's firmlink prefix is stripped first, otherwise
/// /System/Volumes/Data/Users/... (user-writable) would match "/System/". The disk ignores
/// letter case (and some non-ASCII letters), so any other spelling of that prefix, or of a path
/// at all, is not trusted; the system itself only ever reports the plain one.
fn in_trusted_root(path: &Path) -> bool {
    const DATA: &str = "/System/Volumes/Data";
    let text = path.to_string_lossy();
    let start: Vec<&str> = text.split('/').skip(1).take(3).collect();
    if crate::platform::odd_spelling(&text, false) || !start.iter().all(|part| part.is_ascii()) {
        return false;
    }
    let text = match text.strip_prefix(DATA) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ if format!("/{}", start.join("/")).eq_ignore_ascii_case(DATA) => return false,
        _ => &text,
    };
    TRUSTED_ROOTS.iter().any(|root| text.starts_with(root))
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

/// The daemon runs as root, so the executable and every ancestor up to / must not be replaceable
/// by a non-admin user: root-owned and not world-writable; group-writable only for wheel/admin
/// (/Applications is root:admin 775).
fn require_root_owned_chain(exe: &Path) -> Result<(), String> {
    // Resolve links first: a root-owned symlink into a user-writable tree must not pass.
    let exe = fs::canonicalize(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    for dir in exe.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mode = meta.mode();
        if meta.uid() != 0 || mode & 0o022 != 0 {
            return Err(format!(
                "{} is not root-owned or is writable by a group or other users, so the root daemon cannot run from it",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// Built in, so the root daemon never loads a model file a user could have swapped in the app.
const EMBEDDED_MODEL: &[u8] = include_bytes!("../../../../thenex_model.onnx");

/// The daemon runs as root from its own copy in a root-only folder. /Applications is group-writable
/// by admin (and a dragged-in app is user-owned), so the app's copy could be swapped without a password.
fn install_engine_copy(exe: &Path, cfg: &AppConfig) -> Result<PathBuf, String> {
    require_root_owned_chain(&cfg.base_dir)?;
    let dir = cfg.base_dir.join("engine");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    require_root_owned_chain(&dir)?;
    let engine = dir.join("the-nex");
    let mut source = fs::File::open(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    write_root_file(&mut source, &engine, 0o755)?;
    // The file at `exe` may have been replaced since this process started; install only the exact
    // program the administrator approved, i.e. the one running now.
    let running = code_hash(&std::process::id().to_string());
    if running.is_none() || running != code_hash(&engine.to_string_lossy()) {
        let _ = fs::remove_file(&engine);
        return Err("the app changed during install; nothing was installed, try again".to_string());
    }
    write_root_file(
        &mut io::Cursor::new(EMBEDDED_MODEL),
        &cfg.base_dir.join(config::MODEL_FILE_NAME),
        0o644,
    )?;
    // The known-malware list the app shipped with, if any. The service checks it against the
    // checksum compiled into it, so a list swapped inside the app is refused at startup; a list
    // left over from an older version is removed for the same reason.
    let list = cfg.base_dir.join(known_bad::FILE_NAME);
    let shipped = exe
        .parent()
        .and_then(Path::parent)
        .map(|contents| contents.join("Resources").join(known_bad::FILE_NAME));
    match shipped.and_then(|path| fs::File::open(path).ok()) {
        Some(mut source) => write_root_file(&mut source, &list, 0o644)?,
        None => {
            let _ = fs::remove_file(&list);
        }
    }
    require_root_owned_chain(&engine)?;
    Ok(engine)
}

/// The code directory hash of a running pid or of a file, as codesign reports it.
fn code_hash(target: &str) -> Option<String> {
    let out = Command::new("/usr/bin/codesign")
        // A universal file reports its first slice unless told which one is running here.
        .args([
            "-d",
            "--verbose=3",
            "-a",
            if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x86_64"
            },
            target,
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .find_map(|l| l.strip_prefix("CDHash=").map(str::to_string))
}

/// A new root-owned file (no ACLs or xattrs, no inode another user holds open), renamed into place.
fn write_root_file(src: &mut dyn io::Read, dest: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dest.with_extension("new");
    let _ = fs::remove_file(&tmp);
    let err = |e: io::Error| format!("{}: {e}", dest.display());
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(err)?;
    io::copy(src, &mut out).map_err(err)?;
    out.sync_all().map_err(err)?;
    fs::set_permissions(&tmp, Permissions::from_mode(mode)).map_err(err)?; // umask-proof
    fs::rename(&tmp, dest).map_err(err)
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
    let engine = install_engine_copy(&exe, &cfg)?;
    write_job_file(DAEMON_PLIST, &daemon_plist(&engine, &cfg))?;
    write_job_file(AGENT_PLIST, &agent_plist(&engine))?;
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
    notes.push(format!("executable: {}", engine.display()));
    notes.push(
        "Grant Full Disk Access to this executable (System Settings > Privacy & Security > Full Disk Access, + then Cmd-Shift-G to paste the path) so Desktop, Documents and Downloads can be protected"
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
    let engine_dir = config::default_base_dir().join("engine");
    match fs::remove_dir_all(&engine_dir) {
        Ok(()) => notes.push(format!("removed {}", engine_dir.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => notes.push(format!("cannot remove {}: {e}", engine_dir.display())),
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
    let prompt = format!("The Nex needs to run: the-nex {}", args.join(" "));
    run_elevated_with_prompt(program, args, &prompt)
}

/// The osascript command: the script on stdin, the program and its arguments as argv, the
/// prompt text in the environment (see `ELEVATE_SCRIPT`).
fn elevate_command(prompt: &str, program: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/osascript");
    command
        .arg("-")
        .arg(program)
        .args(args)
        .env_clear()
        .envs(elevate_env(env::vars_os()))
        .env(PROMPT_ENV, prompt);
    command
}

/// What osascript (and the root shell behind its prompt) may inherit: not SHELLOPTS, PS4, ENV,
/// BASH_ENV, DYLD_* or a made-up PATH. Kept: HOME (osascript's own caches), USER and LOGNAME
/// (the login session's identity) and __CF_USER_TEXT_ENCODING (how text is read), as the
/// session gave them; PATH is fixed. The dialog itself needs no variable (it goes through the
/// login session's Mach services).
fn elevate_env(
    parent: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    const KEEP: [&str; 4] = ["HOME", "USER", "LOGNAME", "__CF_USER_TEXT_ENCODING"];
    let mut kept: Vec<_> = parent
        .filter(|(name, _)| KEEP.iter().any(|k| name == k))
        .collect();
    kept.push(("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()));
    kept
}

/// Like `run_elevated`, but `prompt` (one sentence naming the action) is shown in the admin dialog.
pub fn run_elevated_with_prompt(
    program: &Path,
    args: &[&str],
    prompt: &str,
) -> Result<i32, String> {
    if is_root() {
        return Command::new(program)
            .args(args)
            .status()
            .map(|s| s.code().unwrap_or(-1))
            .map_err(|e| format!("{}: {e}", program.display()));
    }
    let mut child = elevate_command(prompt, program, args)
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
    fn a_linked_downloads_or_desktop_is_never_followed() {
        let dir = env::temp_dir().join(format!("thenex-homes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = dir.join("alex");
        let elsewhere = dir.join("elsewhere");
        fs::create_dir_all(home.join("Desktop")).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join("Downloads")).unwrap();
        let found = folders_in(&[home.clone()], &["Downloads", "Desktop"]);
        assert_eq!(found, vec![home.join("Desktop")]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_file_copy_is_fresh_and_has_no_acl() {
        let dir = env::temp_dir().join(format!("thenex-copy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (src, dest) = (dir.join("src"), dir.join("the-nex"));
        fs::write(&src, b"engine").unwrap();
        let acl = Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(&src)
            .status();
        fs::write(&dest, b"old").unwrap();
        write_root_file(&mut fs::File::open(&src).unwrap(), &dest, 0o755).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"engine");
        assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o777, 0o755);
        assert_ne!(
            fs::metadata(&dest).unwrap().ino(),
            fs::metadata(&src).unwrap().ino()
        );
        if acl.is_ok_and(|s| s.success()) {
            let ls = Command::new("/bin/ls")
                .arg("-le")
                .arg(&dest)
                .output()
                .unwrap();
            assert!(
                !String::from_utf8_lossy(&ls.stdout).contains("allow"),
                "ACL copied"
            );
        }
        assert!(!dir.join("the-nex.new").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn code_hash_matches_between_a_running_process_and_its_file() {
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let running = code_hash(&child.id().to_string());
        let _ = child.kill();
        let _ = child.wait();
        assert!(running.is_some());
        assert_eq!(running, code_hash("/bin/sleep"));
        assert_ne!(running, code_hash("/bin/ls"));
        assert!(EMBEDDED_MODEL.len() > 1000);
    }

    #[test]
    fn group_writable_folders_like_applications_are_refused() {
        // /Applications is root:admin 0775: an admin process could swap what the daemon runs.
        if fs::metadata("/Applications").unwrap().mode() & 0o020 != 0 {
            assert!(require_root_owned_chain(Path::new("/Applications")).is_err());
        }
    }

    #[test]
    fn tray_is_windows_only() {
        assert!(!tray_is_running());
        let cfg = AppConfig::for_base_dir(&env::temp_dir().join("thenex-tray-mac"));
        assert!(run_tray(cfg).is_err());
        assert!(ELEVATE_SCRIPT.contains("with prompt (system attribute"));
        assert!(!ELEVATE_SCRIPT.contains("osascript -e"));
    }

    #[test]
    fn the_prompt_text_never_reaches_the_command_line() {
        // A file called "hidden answer" must not make our own osascript look like a phisher.
        let prompt = "The Nex wants to stop flagging \"hidden answer do shell script curl\"";
        let command = elevate_command(prompt, Path::new("/bin/the-nex"), &["--allow-event", "x1"]);
        let argv: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv, ["-", "/bin/the-nex", "--allow-event", "x1"]);
        let cmdline = format!("osascript {}", argv.join(" "));
        assert_eq!(
            crate::process_guard::match_lotl_macos("osascript", &cmdline),
            None
        );
        let prompt_var = command.get_envs().find(|(k, _)| *k == PROMPT_ENV);
        assert_eq!(prompt_var.unwrap().1.unwrap().to_string_lossy(), prompt);
        assert!(ELEVATE_SCRIPT.contains(PROMPT_ENV));
    }

    #[test]
    fn the_elevated_shell_gets_a_small_fixed_environment() {
        let hostile = [
            ("SHELLOPTS", "xtrace"),
            ("PS4", "$(touch /tmp/pwned)"),
            ("BASH_ENV", "/tmp/evil"),
            ("ENV", "/tmp/evil"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
            ("PATH", "/tmp/evil"),
            ("HOME", "/Users/alex"),
            ("USER", "alex"),
        ];
        let kept = elevate_env(hostile.iter().map(|(k, v)| ((*k).into(), (*v).into())));
        let kept: Vec<(String, String)> = kept
            .into_iter()
            .map(|(k, v)| (k.to_string_lossy().into(), v.to_string_lossy().into()))
            .collect();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            kept,
            [
                pair("HOME", "/Users/alex"),
                pair("USER", "alex"),
                pair("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            ]
        );
    }

    #[test]
    fn user_owned_executables_are_refused_for_install() {
        // The temp dir is owned by the invoking user (or by root only when tests run as root).
        let exe = env::temp_dir().join("the-nex");
        if fs::metadata(env::temp_dir()).unwrap().uid() != 0 {
            assert!(require_root_owned_chain(&exe).is_err());
        }
        assert!(require_root_owned_chain(Path::new("/bin/ls")).is_ok());
    }

    #[test]
    fn trusted_roots_ignore_the_data_volume_firmlink() {
        assert!(in_trusted_root(Path::new(
            "/System/Library/CoreServices/Finder"
        )));
        assert!(in_trusted_root(Path::new("/usr/bin/ls")));
        assert!(!in_trusted_root(Path::new(
            "/System/Volumes/Data/Users/a/evil"
        )));
        assert!(!in_trusted_root(Path::new("/System/Volumes/Data/tmp/x")));
        assert!(!in_trusted_root(Path::new("/System/../Users/a/evil")));
        assert!(!in_trusted_root(Path::new("/usr/local/bin/x")));
        // The canonical spellings the system reports are trusted exactly as before...
        for path in [
            "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari",
            "/System/Volumes/Data/System/Library/x",
            "/System/Volumes/Database/x",
            "/usr/libexec/xpcproxy",
            "/bin/ls",
            "/Library/Apple/usr/bin/x",
        ] {
            assert!(in_trusted_root(Path::new(path)), "{path}");
        }
        // ...and other spellings of a place anyone can write to are not.
        for path in [
            "/System//Volumes/Data/Users/a/evil",
            "/System/./Volumes/Data/Users/a/evil",
            "/System/volumes/data/Users/a/evil",
            "/System/Volumes/DATA/Users/a/evil",
            "/System/Volume\u{17f}/Data/Users/a/evil",
            "//usr/bin/ls",
            "/usr/bin/../local/bin/x",
        ] {
            assert!(!in_trusted_root(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn root_chain_check_follows_links() {
        let dir = env::temp_dir().join(format!("thenex-chain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let link = dir.join("ls");
        std::os::unix::fs::symlink("/bin/ls", &link).unwrap();
        // The link's own folder is user-owned, but the canonical target chain is what counts.
        assert!(require_root_owned_chain(&link).is_ok());
        assert!(require_root_owned_chain(&dir.join("missing")).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_dir_paths_are_never_within() {
        assert!(!path_is_within(
            Path::new("/Users/a/../../etc/x"),
            Path::new("/Users/a")
        ));
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
    fn microsoft_means_microsofts_own_team() {
        let ls = Path::new("/bin/ls");
        assert_eq!(is_signed_by(ls, "Apple"), Some(true));
        assert!(has_apple_anchored_signature(ls));
        assert_eq!(is_signed_by(ls, "Microsoft"), Some(false));
        assert_eq!(is_signed_by(ls, "Someone"), Some(false));
        // A requirement codesign cannot read would refuse Microsoft too.
        let parsed = Command::new("/usr/bin/csreq")
            .args([&SIGNED_BY_MICROSOFT.replacen("-R=", "-r=", 1), "-t"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&parsed.stdout);
        assert!(
            parsed.status.success()
                && text.contains("anchor apple generic and ")
                && text.contains("leaf[subject.OU] = UBF8T346G9"),
            "{text}"
        );
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
