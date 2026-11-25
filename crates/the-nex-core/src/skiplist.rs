//! "Never scan": folders and files whose contents The Nex must not open, move or delete. The
//! list (`never_scan.json`) sits beside settings.json and has the same protection as the
//! always-allowed list (see `allowlist`): changing it takes an administrator, because a program
//! that could add itself would never be looked at again. Unlike that list it goes by place, so
//! whatever is put in a listed folder later is skipped too; that is the point, and the risk.
//!
//! What is not about files stays on: dangerous command lines and the ransomware decoys elsewhere.

use crate::allowlist::{self, LoadError};
use crate::check_file;
use crate::config::{self, AppConfig};
use crate::logger::lock_or_recover;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILE_NAME: &str = "never_scan.json";
pub const EVENT: &str = "NEVER_SCAN";
pub const MAX_ENTRIES: usize = 100;
const MAX_PATH_CHARS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkippedPlace {
    pub path: String,
    pub folder: bool,
    pub added_at: DateTime<Utc>,
}

/// Places where skipping would blind the engine: what starts by itself, temporary folders (where
/// most malware first lands) and the system. Lower case, "*" is any one name. Neither these, nor
/// anything inside them, nor a folder that holds one of them can be listed.
const MAC_PLACES: &[&[&str]] = &[
    &["system"],
    &["library"],
    &["usr"],
    &["bin"],
    &["sbin"],
    &["private"],
    &["tmp"],
    &["var"],
    &["etc"],
    &["dev"],
    &["users", "*", "library", "launchagents"],
];
const WINDOWS_PLACES: &[&[&str]] = &[
    &["windows"],
    &["$recycle.bin"],
    &["programdata", "microsoft"],
    &["users", "*", "appdata", "local", "temp"],
    &[
        "users",
        "*",
        "appdata",
        "roaming",
        "microsoft",
        "windows",
        "start menu",
    ],
];

/// Why the place with this `platform::path_key` is too much to skip.
fn too_much(key: &str, windows: bool) -> Option<&'static str> {
    const TOO_MUCH: &str =
        "That would leave out too much of this computer. Choose a folder further in.";
    let mut parts = key.split(if windows { '\\' } else { '/' });
    let root = parts.next().unwrap_or_default();
    let drive = root.len() == 2 && root.ends_with(':');
    if (windows && !drive) || (!windows && !root.is_empty()) {
        return Some("Only a full path on this computer can be listed.");
    }
    let parts: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();
    // An external drive or disk image on a Mac is /Volumes/<name>.
    let whole_drive = usize::from(!windows && parts.first() == Some(&"volumes"));
    if parts.len() < 2 + whole_drive {
        return Some(TOO_MUCH);
    }
    let places = if windows { WINDOWS_PLACES } else { MAC_PLACES };
    places
        .iter()
        .any(|place| {
            place
                .iter()
                .zip(&parts)
                .all(|(want, part)| *want == "*" || want == part)
        })
        .then_some(
            "The Nex has to watch that place: it is part of the system, or holds programs that start by themselves or temporary files.",
        )
}

/// Windows answers `\\?\C:\x`; people and the event log know it as `C:\x`.
fn plain(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

/// The entry for an existing folder or file, spelled the way the disk spells it (links followed),
/// or a plain-language reason why it cannot be listed.
pub fn resolve(path: &Path) -> Result<SkippedPlace, String> {
    if !path.is_absolute() {
        return Err("Give the full path of a folder or file.".to_string());
    }
    let real = fs::canonicalize(path)
        .map(plain)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => "That folder or file could not be found.".to_string(),
            _ => format!("That folder or file could not be looked up: {e}"),
        })?;
    let meta = fs::symlink_metadata(&real).map_err(|e| format!("It could not be read: {e}"))?;
    if !meta.is_dir() && !meta.is_file() {
        return Err("Only a folder or an ordinary file can be listed.".to_string());
    }
    let text = real
        .to_str()
        .ok_or("Its name cannot be written as text, so it cannot be listed.")?;
    check_text(text)?;
    Ok(SkippedPlace {
        path: text.to_string(),
        folder: meta.is_dir(),
        added_at: Utc::now(),
    })
}

/// What every entry must be, however it got into the file.
fn check_text(text: &str) -> Result<(), String> {
    if text.chars().count() > MAX_PATH_CHARS {
        return Err("That path is too long to be listed.".to_string());
    }
    // It is shown in the administrator prompt: it must read as what it is.
    if text
        .chars()
        .any(|c| c.is_control() || check_file::is_invisible_format(c))
    {
        return Err("Its name holds invisible characters, so it cannot be listed.".to_string());
    }
    if platform::odd_spelling(text, cfg!(windows)) {
        return Err("That is not the plain full path of a folder or file.".to_string());
    }
    match too_much(&platform::path_key(Path::new(text)), cfg!(windows)) {
        Some(why) => Err(why.to_string()),
        None => Ok(()),
    }
}

/// Loads the list. A missing file is an empty list; a damaged or untrusted one is an error and is
/// never partly used.
pub fn load(path: &Path, privileged: bool) -> Result<Vec<SkippedPlace>, LoadError> {
    let Some(bytes) = allowlist::read_protected(path, privileged)? else {
        return Ok(Vec::new());
    };
    let damaged = |why: String| LoadError::Damaged(format!("damaged: {why}"));
    let places: Vec<SkippedPlace> =
        serde_json::from_slice(&bytes).map_err(|e| damaged(e.to_string()))?;
    let mut seen = HashSet::new();
    if places.len() > MAX_ENTRIES {
        return Err(damaged("the list is over its limit".to_string()));
    }
    for place in &places {
        check_text(&place.path).map_err(damaged)?;
        if !seen.insert(platform::path_key(Path::new(&place.path))) {
            return Err(damaged("a place is listed twice".to_string()));
        }
    }
    Ok(places)
}

#[derive(Debug, Default)]
struct Loaded {
    stamp: Option<allowlist::ListStamp>,
    /// `platform::path_key` and whether it is a folder.
    places: Vec<(String, bool)>,
    error: Option<String>,
}

impl Loaded {
    fn covers(&self, path: &Path) -> bool {
        let key = platform::path_key(path);
        !platform::has_parent_dir(path)
            && self.places.iter().any(|(listed, folder)| {
                match key.strip_prefix(listed.as_str()) {
                    // A listed file that something replaced by a folder is not a listed folder.
                    Some("") => *folder || !fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()),
                    Some(rest) => *folder && rest.starts_with(std::path::MAIN_SEPARATOR),
                    None => false,
                }
            })
    }
}

/// The Mac's other name for everything on the main disk but the system.
const MAC_DATA_VOLUME: &str = "/system/volumes/data";

/// The list as a running process sees it: re-read when the file changes.
#[derive(Debug)]
pub struct LiveSkipped {
    path: PathBuf,
    state: Mutex<Loaded>,
}

impl LiveSkipped {
    pub fn new(path: PathBuf) -> Self {
        let live = Self {
            path,
            state: Mutex::default(),
        };
        live.refresh();
        live
    }

    /// One stat; reads the file only when it changed.
    pub fn refresh(&self) {
        self.refresh_with(|path| load(path, config::running_privileged()));
    }

    fn refresh_with(&self, load: impl FnOnce(&Path) -> Result<Vec<SkippedPlace>, LoadError>) {
        let stamp = allowlist::list_stamp(&self.path);
        let mut state = lock_or_recover(&self.state);
        if state.stamp == Some(stamp) {
            return;
        }
        match load(&self.path) {
            Ok(places) => {
                *state = Loaded {
                    stamp: Some(stamp),
                    places: places
                        .iter()
                        .map(|p| (platform::path_key(Path::new(&p.path)), p.folder))
                        .collect(),
                    error: None,
                };
            }
            // Tried again next time. What an administrator listed stays in force meanwhile: a
            // moment's read error must not open private folders.
            Err(LoadError::Io(e)) => {
                state.stamp = None;
                state.error = Some(e.to_string());
            }
            Err(e) => {
                *state = Loaded {
                    stamp: Some(stamp),
                    places: Vec::new(),
                    error: Some(e.to_string()),
                };
            }
        }
    }

    /// True for a listed folder or file and everything inside a listed folder.
    pub fn covers(&self, path: &Path) -> bool {
        {
            let state = lock_or_recover(&self.state);
            if state.places.is_empty() {
                return false;
            }
            if state.covers(path) {
                return true;
            }
            if cfg!(target_os = "macos") {
                let text = path.to_string_lossy();
                let other_name = text
                    .get(..MAC_DATA_VOLUME.len())
                    .filter(|start| start.eq_ignore_ascii_case(MAC_DATA_VOLUME))
                    .map(|start| Path::new(&text[start.len()..]));
                if other_name.is_some_and(|rest| rest.is_absolute() && state.covers(rest)) {
                    return true;
                }
            }
        }
        // A spelling the text comparison cannot see through (`..`, a Windows short name).
        platform::odd_spelling(&path.to_string_lossy(), cfg!(windows))
            && fs::canonicalize(path).is_ok_and(|real| lock_or_recover(&self.state).covers(&real))
    }

    /// Why the file is being ignored, if it is.
    pub fn error(&self) -> Option<String> {
        lock_or_recover(&self.state).error.clone()
    }

    /// The listed places as `platform::path_key`s, and whether each is a folder.
    pub fn places(&self) -> Vec<(String, bool)> {
        lock_or_recover(&self.state).places.clone()
    }
}

/// Lists one existing folder or file (false: already listed). `path` must already be what it
/// leads to, and of the kind the person was asked about: a link or folder swapped in after they
/// saw the prompt is refused. Fails with `PermissionDenied` for anyone who cannot write the data
/// folder.
pub fn add(cfg: &AppConfig, path: &Path, folder: bool) -> io::Result<bool> {
    let place = resolve(path).map_err(allowlist::invalid)?;
    if place.folder != folder {
        return Err(allowlist::invalid(if folder {
            "that is a file, not a folder"
        } else {
            "that is a folder, not a file"
        }));
    }
    let key = platform::path_key(Path::new(&place.path));
    if key != platform::path_key(path) {
        return Err(allowlist::invalid(format!(
            "that path leads to {}; give that one if it is what you mean",
            place.path
        )));
    }
    let _lock = allowlist::lock(&cfg.skipped_file, allowlist::LOCK_WAIT)?;
    let mut places = allowlist::load_for_update(&cfg.skipped_file, load)?;
    if places
        .iter()
        .any(|p| platform::path_key(Path::new(&p.path)) == key)
    {
        return Ok(false);
    }
    if places.len() >= MAX_ENTRIES {
        return Err(allowlist::invalid(format!(
            "the list is full ({MAX_ENTRIES} places)"
        )));
    }
    let shown = place.path.clone();
    places.push(place);
    save(cfg, &places)?;
    audit(cfg, "ADDED", &shown);
    Ok(true)
}

/// Takes one place off the list, whether or not it still exists; false when it was not listed (a
/// damaged list lists nothing).
pub fn remove(cfg: &AppConfig, path: &Path) -> io::Result<bool> {
    let key = platform::path_key(path);
    let _lock = allowlist::lock(&cfg.skipped_file, allowlist::LOCK_WAIT)?;
    let mut places = match load(&cfg.skipped_file, config::running_privileged()) {
        Err(LoadError::Damaged(_)) => return Ok(false),
        _ => allowlist::load_for_update(&cfg.skipped_file, load)?,
    };
    let before = places.len();
    places.retain(|p| platform::path_key(Path::new(&p.path)) != key);
    if places.len() == before {
        return Ok(false);
    }
    save(cfg, &places)?;
    audit(cfg, "REMOVED", &path.display().to_string());
    Ok(true)
}

fn save(cfg: &AppConfig, places: &[SkippedPlace]) -> io::Result<()> {
    let body = serde_json::to_vec_pretty(places).map_err(io::Error::other)?;
    config::write_atomic(&cfg.skipped_file, &body)?;
    cfg.skipped.refresh();
    Ok(())
}

fn audit(cfg: &AppConfig, action: &str, path: &str) {
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            EVENT,
            Severity::Low,
            path,
            action,
            "the never-scan list was changed",
        ),
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A folder that may be listed: the temporary folder other tests use may not.
    pub(crate) fn listable(tag: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("thenex-skip-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        plain(fs::canonicalize(dir).unwrap())
    }

    fn setup(tag: &str) -> (PathBuf, AppConfig) {
        let dir = listable(tag);
        let cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
        cfg.ensure_dirs().unwrap();
        (dir, cfg)
    }

    #[test]
    fn a_listed_folder_covers_what_is_inside_and_nothing_beside_it() {
        let (dir, cfg) = setup("covers");
        let private = dir.join("Private");
        fs::create_dir_all(private.join("deep")).unwrap();
        fs::write(dir.join("one.txt"), b"x").unwrap();
        assert!(!cfg.skipped.covers(&private));
        assert!(add(&cfg, &private, true).unwrap());
        assert!(!add(&cfg, &private, true).unwrap(), "already listed");
        assert!(add(&cfg, &dir.join("one.txt"), true).is_err(), "a file");
        assert!(add(&cfg, &private, false).is_err(), "a folder");
        assert!(add(&cfg, &dir.join("one.txt"), false).unwrap());
        for inside in [
            private.clone(),
            private.join("deep").join("a.exe"),
            dir.join("PRIVATE").join("gone.zip"),
            dir.join("one.txt"),
        ] {
            assert!(cfg.skipped.covers(&inside), "{}", inside.display());
        }
        for outside in [
            dir.clone(),
            dir.join("Private2").join("a.exe"),
            dir.join("Privat"),
            dir.join("one.txt.exe"),
            private.join("..").join("a.exe"),
        ] {
            assert!(!cfg.skipped.covers(&outside), "{}", outside.display());
        }
        // Spelled with "..", an existing file is still recognised for where it really is.
        fs::write(private.join("real.zip"), b"x").unwrap();
        let odd = private.join("deep").join("..").join("real.zip");
        assert!(cfg.skipped.covers(&odd));

        #[cfg(target_os = "macos")]
        {
            let data = format!("/System/Volumes/Data{}", private.join("real.zip").display());
            assert!(cfg.skipped.covers(Path::new(&data)));
            assert!(!cfg.skipped.covers(Path::new("/System/Volumes/Data")));
            let beside = format!("/System/Volumes/Data{}", dir.join("x").display());
            assert!(!cfg.skipped.covers(Path::new(&beside)));
        }
        // A listed file that becomes a folder does not become a listed folder.
        fs::remove_file(dir.join("one.txt")).unwrap();
        fs::create_dir(dir.join("one.txt")).unwrap();
        assert!(!cfg.skipped.covers(&dir.join("one.txt")));
        assert!(!cfg.skipped.covers(&dir.join("one.txt").join("evil.exe")));
        fs::remove_dir(dir.join("one.txt")).unwrap();

        assert!(remove(&cfg, &dir.join("PRIVATE")).unwrap());
        assert!(!remove(&cfg, &private).unwrap());
        assert!(!cfg.skipped.covers(&private) && cfg.skipped.covers(&dir.join("one.txt")));
        let actions: Vec<String> = quarantine::read_recent_events(&cfg.events_log, 1 << 20)
            .unwrap()
            .into_iter()
            .filter(|e| e.threat_type == EVENT)
            .map(|e| e.action_taken)
            .collect();
        assert_eq!(actions, ["REMOVED", "ADDED", "ADDED"], "newest first");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn whole_disks_homes_and_places_malware_starts_from_cannot_be_listed() {
        for key in [
            "/",
            "/users",
            "/users/me",
            "/users/shared",
            "/applications",
            "/volumes/usb",
            "/library/launchdaemons",
            "/private/tmp/x",
            "/tmp/x",
            "/var/folders/ab",
            "/usr/local/bin",
            "/users/me/library",
            "/users/me/library/launchagents",
            "/users/me/library/launchagents/x.plist",
            "users/me/x",
            "",
        ] {
            assert!(too_much(key, false).is_some(), "{key}");
        }
        for key in [
            "/users/me/documents",
            "/users/me/documents/tax",
            "/users/me/downloads",
            "/users/me/library/mail",
            "/users/library/x",
            "/applications/thing.app",
            "/volumes/usb/photos",
            "/opt/homebrew",
        ] {
            assert_eq!(too_much(key, false), None, "{key}");
        }
        for key in [
            r"c:\",
            "c:",
            r"c:\users",
            r"c:\users\me",
            r"c:\program files",
            r"c:\windows\temp",
            r"d:\windows",
            r"c:\programdata\microsoft\windows",
            r"c:\users\me\appdata",
            r"c:\users\me\appdata\local",
            r"c:\users\me\appdata\local\temp\x",
            r"c:\users\me\appdata\roaming\microsoft",
            r"\\server\share\docs\x",
            r"\\.\globalroot\x\y",
            "/users/me/documents",
        ] {
            assert!(too_much(key, true).is_some(), "{key}");
        }
        for key in [
            r"c:\users\me\documents",
            r"c:\users\me\appdata\local\vendor",
            r"d:\work\tax",
            r"c:\program files\vendor",
        ] {
            assert_eq!(too_much(key, true), None, "{key}");
        }
    }

    #[test]
    fn only_a_real_plain_path_can_be_added() {
        let (dir, cfg) = setup("plain");
        let folder = dir.join("folder");
        fs::create_dir(&folder).unwrap();
        for bad in [
            Path::new("folder").to_path_buf(),
            dir.join("gone"),
            folder.join("..").join("folder"),
            std::env::temp_dir(),
        ] {
            assert!(add(&cfg, &bad, true).is_err(), "{}", bad.display());
        }
        #[cfg(unix)]
        {
            // A link is never followed by the writer, so nobody can swap one in after the prompt.
            std::os::unix::fs::symlink(&folder, dir.join("link")).unwrap();
            let error = add(&cfg, &dir.join("link"), true).unwrap_err().to_string();
            assert!(error.contains("leads to"), "{error}");
            assert_eq!(
                resolve(&dir.join("link")).unwrap().path,
                folder.to_str().unwrap()
            );
            fs::create_dir(dir.join("a\u{202E}b")).unwrap();
            assert!(add(&cfg, &dir.join("a\u{202E}b"), true).is_err());
            fs::create_dir(dir.join("a\nb")).unwrap();
            assert!(add(&cfg, &dir.join("a\nb"), true).is_err());
        }
        assert!(cfg.skipped.places().is_empty() && !cfg.skipped_file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_or_tampered_list_skips_nothing_and_a_read_error_changes_nothing() {
        let (dir, cfg) = setup("damaged");
        let folder = dir.join("folder");
        fs::create_dir(&folder).unwrap();
        assert!(add(&cfg, &folder, true).unwrap());
        assert!(cfg.skipped.covers(&folder));

        lock_or_recover(&cfg.skipped.state).stamp = None;
        cfg.skipped
            .refresh_with(|_| Err(LoadError::Io(io::Error::other("busy"))));
        assert!(cfg.skipped.covers(&folder), "still in force");
        assert!(cfg.skipped.error().is_some());
        cfg.skipped.refresh();
        assert!(cfg.skipped.error().is_none());

        let good = fs::read_to_string(&cfg.skipped_file).unwrap();
        let entry = |path: &str| {
            serde_json::to_vec(&[SkippedPlace {
                path: path.to_string(),
                folder: true,
                added_at: Utc::now(),
            }])
            .unwrap()
        };
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let dots = format!("{}/../folder", folder.display());
        for bad in [
            b"not json".to_vec(),
            entry(root),
            entry("relative"),
            entry(&dots),
        ] {
            fs::write(&cfg.skipped_file, &bad).unwrap();
            lock_or_recover(&cfg.skipped.state).stamp = None;
            cfg.skipped.refresh();
            assert!(!cfg.skipped.covers(&folder) && cfg.skipped.error().is_some());
        }
        fs::write(&cfg.skipped_file, good).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cfg.skipped_file, fs::Permissions::from_mode(0o666)).unwrap();
            cfg.skipped.refresh();
            assert!(!cfg.skipped.covers(&folder), "anyone could have written it");
            assert!(
                add(&cfg, &folder, true).is_err(),
                "and it is not overwritten"
            );
            assert!(load(&cfg.skipped_file, true).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_is_capped() {
        let (dir, cfg) = setup("cap");
        for n in 0..MAX_ENTRIES {
            let folder = dir.join(format!("f{n}"));
            fs::create_dir(&folder).unwrap();
            assert!(add(&cfg, &folder, true).unwrap());
        }
        fs::create_dir(dir.join("more")).unwrap();
        assert!(add(&cfg, &dir.join("more"), true).is_err());
        assert_eq!(cfg.skipped.places().len(), MAX_ENTRIES);
        let _ = fs::remove_dir_all(&dir);
    }
}
