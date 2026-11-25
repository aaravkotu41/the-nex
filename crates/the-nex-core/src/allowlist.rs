//! "Always allow" for one exact file. The list (`allowed.json`) holds SHA-256 hashes the AI and
//! zip-bomb engines must not flag again. It sits beside settings.json and has the same
//! protection: only someone who can write the data folder can change it, so malware running as
//! the normal user cannot allow itself. A privileged service goes further and ignores a file
//! that is not owned by root or that others can write.
//!
//! Matching is by SHA-256 only, never by path or name, so a changed file is checked again. A
//! hash on the known-malware list is never allowed, whatever this list says, and scripts
//! (LotL) and canaries have no file hash and so cannot be listed at all.

use crate::config::{self, AppConfig};
use crate::known_bad::Digest32;
use crate::logger::{self, lock_or_recover};
use crate::quarantine::{self, QuarantineMeta, Severity, ThreatEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

pub const FILE_NAME: &str = "allowed.json";
pub const MAX_ENTRIES: usize = 1000;
const MAX_NAME_CHARS: usize = 120;
/// 1,000 entries are well under 1 MB; a bigger file is not ours.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Detections an entry can cover: whole files judged by an estimating engine. `MANUAL` is for
/// an entry added by hand from the command line.
pub const ALLOWABLE_TYPES: &[&str] = &["MALWARE_AI", "MALWARE_AI_PROCESS", "ZIP_BOMB", "MANUAL"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowedFile {
    pub sha256: String,
    pub name: String,
    pub threat_type: String,
    pub added_at: DateTime<Utc>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// 64 hex digits, returned lower-case.
pub fn parse_sha256(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err("a SHA-256 is 64 hexadecimal characters".to_string())
    }
}

/// A shown name only: control characters and a leading `-` (which a command line would read as
/// an option) are replaced, and the length is bounded.
pub fn clean_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_NAME_CHARS)
        .collect();
    match cleaned.trim() {
        "" => "unnamed".to_string(),
        name => match name.strip_prefix('-') {
            Some(rest) => format!("_{rest}"),
            None => name.to_string(),
        },
    }
}

/// The CLI is strict: a name with a control character or an over-long one is an error.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("the name must be 1 to {MAX_NAME_CHARS} characters"));
    }
    if name.chars().any(char::is_control) {
        return Err("the name must not contain control characters".to_string());
    }
    Ok(())
}

pub fn check_type(threat_type: &str) -> Result<(), String> {
    if ALLOWABLE_TYPES.contains(&threat_type) {
        Ok(())
    } else {
        Err(format!(
            "{threat_type} detections cannot be always allowed (only {})",
            ALLOWABLE_TYPES.join(", ")
        ))
    }
}

impl AllowedFile {
    pub fn new(sha256: &str, name: &str, threat_type: &str) -> Result<Self, String> {
        check_type(threat_type)?;
        Ok(Self {
            sha256: parse_sha256(sha256)?,
            name: clean_name(name),
            threat_type: threat_type.to_string(),
            added_at: Utc::now(),
        })
    }

    /// From the SHA-256 the engine recorded when it flagged the file, never from a re-read path.
    pub fn from_event(event: &ThreatEvent) -> Result<Self, String> {
        let sha256 = event
            .sha256
            .as_deref()
            .ok_or("this event has no recorded file hash")?;
        let name = Path::new(&event.target).file_name().map_or_else(
            || event.target.clone(),
            |n| n.to_string_lossy().into_owned(),
        );
        Self::new(sha256, &name, &event.threat_type)
    }

    pub fn from_quarantined(meta: &QuarantineMeta) -> Result<Self, String> {
        let name = meta
            .original_path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        Self::new(&meta.sha256, &name, &meta.threat_type)
    }
}

/// Why a list file must not be trusted, from its owner and permission bits. A privileged
/// service wants root as the owner; nobody may let others write it.
#[cfg(unix)]
fn untrusted_reason(uid: u32, mode: u32, privileged: bool) -> Option<&'static str> {
    if mode & 0o022 != 0 {
        Some("other users can write it")
    } else if privileged && uid != 0 {
        Some("it is not owned by root")
    } else {
        None
    }
}

/// Loads the list. A missing file is an empty list; a damaged or untrusted one is an error and
/// is never partly used. shortcut: Windows relies on the ACL of ProgramData\TheNex; upgrade by
/// checking the file's owner SID there as well.
pub fn load(path: &Path, privileged: bool) -> Result<Vec<AllowedFile>, String> {
    let file = match quarantine::open_nofollow(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let meta = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        // Checked on the open handle, so a swap after the open changes nothing.
        use std::os::unix::fs::MetadataExt;
        if let Some(why) = untrusted_reason(meta.uid(), meta.mode(), privileged) {
            return Err(format!("{} is ignored: {why}", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = privileged;
    if meta.len() > MAX_FILE_BYTES {
        return Err("the list is too large to be ours".to_string());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let entries: Vec<AllowedFile> =
        serde_json::from_slice(&bytes).map_err(|e| format!("damaged: {e}"))?;
    let mut seen = HashSet::new();
    let well_formed = entries.len() <= MAX_ENTRIES
        && entries
            .iter()
            .all(|e| parse_sha256(&e.sha256).is_ok_and(|h| h == e.sha256 && seen.insert(h)));
    if well_formed {
        Ok(entries)
    } else {
        Err("damaged: an entry is malformed or the list is over its limit".to_string())
    }
}

#[derive(Debug, Default)]
struct Loaded {
    stamp: Option<(u128, u64, u128)>,
    hashes: HashSet<String>,
    error: Option<String>,
}

/// The list as a running process sees it: re-read when the file changes, so a service honours
/// a new entry within a second without a restart.
#[derive(Debug)]
pub struct LiveAllowed {
    path: PathBuf,
    state: Mutex<Loaded>,
}

impl LiveAllowed {
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
        let stamp = fs::metadata(&self.path).map_or((0, 0, 0), |m| {
            let modified = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
            // ctime also moves on chmod/chown, which must make the trust check run again.
            #[cfg(unix)]
            let changed = {
                use std::os::unix::fs::MetadataExt;
                (m.ctime() as u128) << 32 | m.ctime_nsec() as u128
            };
            #[cfg(not(unix))]
            let changed = 0;
            (modified.map_or(0, |d| d.as_nanos()), m.len(), changed)
        });
        let mut state = lock_or_recover(&self.state);
        if state.stamp == Some(stamp) {
            return;
        }
        state.stamp = Some(stamp);
        match load(&self.path, config::running_privileged()) {
            Ok(entries) => {
                state.hashes = entries.into_iter().map(|e| e.sha256).collect();
                state.error = None;
            }
            Err(e) => {
                state.hashes.clear();
                state.error = Some(e);
            }
        }
    }

    pub fn contains(&self, sha256: &str) -> bool {
        lock_or_recover(&self.state).hashes.contains(sha256)
    }

    /// Why the file is being ignored, if it is.
    pub fn error(&self) -> Option<String> {
        lock_or_recover(&self.state).error.clone()
    }

    pub fn len(&self) -> usize {
        lock_or_recover(&self.state).hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Hashes `path` (the file about to be flagged) and says whether that exact content is always
/// allowed. The hash is returned for the event either way; `None` when the file cannot be
/// hashed (too large, not a regular file), which can never be allowed.
// shortcut: this re-reads the file after the engine judged it, so a swap in between is
// possible; the hash goes into the event and the same bytes are then quarantined or left alone.
// Closing it means hashing the very bytes the engine scored; do that if engines ever keep them.
pub fn check(cfg: &AppConfig, path: &Path) -> (Option<Digest32>, bool) {
    let digest = crate::known_bad::hash_file(path, crate::known_bad::MAX_HASH_BYTES);
    let allowed = digest.is_some_and(|d| cfg.is_allowed(&d));
    if allowed {
        logger::info(format!(
            "{} matches an always-allowed SHA-256; not flagged",
            path.display()
        ));
    }
    (digest, allowed)
}

/// Adds one entry (a no-op returning false when already listed). The caller loads the
/// known-malware list into `cfg` first. Fails with `PermissionDenied` for anyone who cannot
/// write the data folder, which is the whole point.
pub fn add(cfg: &AppConfig, entry: AllowedFile) -> io::Result<bool> {
    let hash = parse_sha256(&entry.sha256).map_err(invalid)?;
    check_type(&entry.threat_type).map_err(invalid)?;
    if cfg.known_bad.contains(&digest_of(&hash)) {
        return Err(invalid(
            "it is on the known-malware list and can never be allowed",
        ));
    }
    // A damaged list is ignored by every reader anyway, so writing replaces it.
    let mut entries = load(&cfg.allowed_file, config::running_privileged()).unwrap_or_default();
    if entries.iter().any(|e| e.sha256 == hash) {
        return Ok(false);
    }
    if entries.len() >= MAX_ENTRIES {
        return Err(invalid(format!("the list is full ({MAX_ENTRIES} files)")));
    }
    let name = entry.name.clone();
    entries.push(AllowedFile {
        sha256: hash.clone(),
        ..entry
    });
    save(cfg, &entries)?;
    audit(cfg, "ADDED", &name, &hash);
    Ok(true)
}

/// The 32 bytes of a hash already checked by `parse_sha256`.
fn digest_of(hex: &str) -> Digest32 {
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("0"), 16).unwrap_or(0);
    }
    digest
}

/// Removes one entry; false when it was not listed.
pub fn remove(cfg: &AppConfig, sha256: &str) -> io::Result<bool> {
    let hash = parse_sha256(sha256).map_err(invalid)?;
    let mut entries = load(&cfg.allowed_file, config::running_privileged()).unwrap_or_default();
    let before = entries.len();
    entries.retain(|e| e.sha256 != hash);
    if entries.len() == before {
        return Ok(false);
    }
    save(cfg, &entries)?;
    audit(cfg, "REMOVED", &hash, &hash);
    Ok(true)
}

fn save(cfg: &AppConfig, entries: &[AllowedFile]) -> io::Result<()> {
    let body = serde_json::to_vec_pretty(entries).map_err(io::Error::other)?;
    config::write_atomic(&cfg.allowed_file, &body)?;
    cfg.allowed.refresh();
    Ok(())
}

fn audit(cfg: &AppConfig, action: &str, target: &str, sha256: &str) {
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "ALLOWLIST",
            Severity::Low,
            target,
            action,
            format!("sha256={sha256}"),
        ),
    );
}

/// Lists the hash from a quarantine record (the bytes that were moved) and restores the file.
/// If the restore fails the hash does not stay allowed.
pub fn allow_and_restore(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    let meta = quarantine::load_meta(id, cfg)?;
    let added = add(cfg, AllowedFile::from_quarantined(&meta).map_err(invalid)?)?;
    match quarantine::restore_file(id, cfg) {
        Ok(meta) => Ok(meta),
        Err(e) => {
            if added {
                let _ = remove(cfg, &meta.sha256);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known_bad;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-allow-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(hash: &str) -> AllowedFile {
        AllowedFile::new(hash, "tool.exe", "MALWARE_AI").unwrap()
    }

    fn hash_n(n: usize) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn input_is_checked_strictly() {
        assert_eq!(
            parse_sha256(&format!(" {} ", HASH.to_uppercase())).unwrap(),
            HASH
        );
        for bad in [
            "",
            "abc",
            &HASH[1..],
            &format!("{HASH}0"),
            &HASH.replace('0', "g"),
        ] {
            assert!(parse_sha256(bad).is_err(), "{bad}");
        }
        assert!(check_name("ok.exe").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_name(&"x".repeat(121)).is_err());
        assert_eq!(clean_name("--evil\x07name"), "_-evil name");
        for allowed in ALLOWABLE_TYPES {
            assert!(check_type(allowed).is_ok());
        }
        for never in [
            "KNOWN_MALWARE",
            "LOTL_SCRIPT",
            "RANSOMWARE_CANARY",
            "RANSOMWARE_SUSPECT",
            "",
        ] {
            assert!(check_type(never).is_err(), "{never}");
        }
    }

    #[test]
    fn a_missing_list_is_empty_and_a_damaged_one_is_refused() {
        let dir = temp("load");
        let file = dir.join(FILE_NAME);
        assert!(load(&file, false).unwrap().is_empty());
        let good = serde_json::to_vec(&[entry(HASH)]).unwrap();
        fs::write(&file, &good).unwrap();
        assert_eq!(load(&file, false).unwrap()[0].sha256, HASH);
        let upper = String::from_utf8(good.clone())
            .unwrap()
            .replace(HASH, &HASH.to_uppercase());
        for damaged in [
            b"not json".to_vec(),
            b"{\"sha256\":1}".to_vec(),
            upper.into_bytes(),
            serde_json::to_vec(&[entry(HASH), entry(HASH)]).unwrap(),
            serde_json::to_vec(&[AllowedFile {
                sha256: "short".to_string(),
                ..entry(HASH)
            }])
            .unwrap(),
        ] {
            fs::write(&file, &damaged).unwrap();
            assert!(load(&file, false).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_is_capped() {
        let dir = temp("cap");
        let cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let full: Vec<AllowedFile> = (0..MAX_ENTRIES).map(|n| entry(&hash_n(n))).collect();
        fs::write(&cfg.allowed_file, serde_json::to_vec(&full).unwrap()).unwrap();
        assert_eq!(load(&cfg.allowed_file, false).unwrap().len(), MAX_ENTRIES);
        assert!(add(&cfg, entry(&hash_n(MAX_ENTRIES))).is_err());
        let over: Vec<AllowedFile> = (0..=MAX_ENTRIES).map(|n| entry(&hash_n(n))).collect();
        fs::write(&cfg.allowed_file, serde_json::to_vec(&over).unwrap()).unwrap();
        assert!(load(&cfg.allowed_file, false).is_err());
        cfg.allowed.refresh();
        assert!(cfg.allowed.is_empty() && cfg.allowed.error().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_and_permissions_decide_trust() {
        assert_eq!(untrusted_reason(0, 0o644, true), None);
        assert_eq!(untrusted_reason(501, 0o644, false), None);
        assert!(
            untrusted_reason(501, 0o644, true).is_some(),
            "a service wants root"
        );
        assert!(untrusted_reason(0, 0o664, true).is_some());
        assert!(untrusted_reason(0, 0o602, false).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_list_others_can_write_is_ignored_by_the_live_view() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("mode");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        add(&cfg, entry(HASH)).unwrap();
        assert!(cfg.allowed.contains(HASH));
        let file = &cfg.allowed_file;
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::set_permissions(file, fs::Permissions::from_mode(0o666)).unwrap();
        cfg.allowed.refresh();
        assert!(!cfg.allowed.contains(HASH));
        assert!(cfg
            .allowed
            .error()
            .unwrap()
            .contains("other users can write"));
        cfg.allowed = std::sync::Arc::new(LiveAllowed::new(cfg.allowed_file.clone()));
        assert!(cfg.allowed.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn someone_who_cannot_write_the_data_folder_cannot_add_an_entry() {
        use std::os::unix::fs::PermissionsExt;
        if config::running_privileged() {
            return; // root writes anywhere
        }
        let dir = temp("denied");
        let cfg = AppConfig::for_base_dir(&dir);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let denied = add(&cfg, entry(HASH)).unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert!(!cfg.allowed_file.exists() && !cfg.allowed.contains(HASH));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_malware_is_never_allowed_and_changes_are_picked_up() {
        let dir = temp("known");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        let digest = digest_of(HASH);
        let list = dir.join("list.bin");
        known_bad::write_list(&list, &[digest], 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        let refused = add(&cfg, entry(HASH)).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        // Even a list written by hand cannot make a listed hash count as allowed.
        fs::write(
            &cfg.allowed_file,
            serde_json::to_vec(&[entry(HASH)]).unwrap(),
        )
        .unwrap();
        assert!(!cfg.is_allowed(&digest));
        assert!(
            cfg.allowed.contains(HASH),
            "it is on the list, but never honoured"
        );

        let other = digest_of(&hash_n(7));
        assert!(!cfg.is_allowed(&other));
        assert!(add(&cfg, entry(&hash_n(7))).unwrap());
        assert!(!add(&cfg, entry(&hash_n(7))).unwrap(), "already listed");
        assert!(cfg.is_allowed(&other));
        assert!(remove(&cfg, &hash_n(7)).unwrap() && !cfg.is_allowed(&other));
        assert!(!remove(&cfg, &hash_n(7)).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn events_and_records_give_the_recorded_hash_and_only_for_allowable_types() {
        let mut event = ThreatEvent::new("MALWARE_AI", Severity::High, "/x/dir/app.bin", "Q", "d");
        assert!(AllowedFile::from_event(&event).is_err(), "no hash recorded");
        event.sha256 = Some(HASH.to_string());
        let found = AllowedFile::from_event(&event).unwrap();
        assert_eq!(
            (found.sha256.as_str(), found.name.as_str()),
            (HASH, "app.bin")
        );
        for never in ["KNOWN_MALWARE", "LOTL_SCRIPT", "RANSOMWARE_CANARY"] {
            event.threat_type = never.to_string();
            assert!(AllowedFile::from_event(&event).is_err(), "{never}");
        }
        // Old logs have no hash and still parse; a missing hash is not written back.
        let old = r#"{"id":"a","timestamp":"2026-01-01T00:00:00Z","threat_type":"ZIP_BOMB","severity":"HIGH","target":"t","action_taken":"x","details":"d"}"#;
        let parsed: ThreatEvent = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.sha256, None);
        assert!(!serde_json::to_string(&parsed).unwrap().contains("sha256"));
    }

    #[test]
    fn restore_and_allow_lists_the_hash_only_if_the_restore_works() {
        let dir = temp("restore");
        let mut cfg = AppConfig::for_base_dir(&dir);
        cfg.ensure_dirs().unwrap();
        cfg.load_known_bad().unwrap();
        let place = |name: &str, kind: &str| {
            let path = dir.join(name);
            fs::write(&path, name.as_bytes()).unwrap();
            let meta = quarantine::quarantine_file(&path, &cfg, kind, "test").unwrap();
            (path, meta)
        };

        let (path, meta) = place("fine.bin", "ZIP_BOMB");
        let restored = allow_and_restore(&meta.id, &cfg).unwrap();
        assert!(path.exists() && restored.sha256 == meta.sha256);
        assert_eq!(load(&cfg.allowed_file, false).unwrap()[0].name, "fine.bin");

        // The destination is taken, so the restore fails and the hash must not stay allowed.
        let (path, meta) = place("blocked.bin", "MALWARE_AI");
        fs::write(&path, b"someone else's file").unwrap();
        assert!(allow_and_restore(&meta.id, &cfg).is_err());
        assert!(!cfg.is_allowed(&digest_of(&meta.sha256)));
        assert!(
            quarantine::load_meta(&meta.id, &cfg).is_ok(),
            "still quarantined"
        );

        // Known malware and anything that is not a file verdict cannot be allowed at all.
        let (path, meta) = place("bad.bin", "KNOWN_MALWARE");
        assert!(allow_and_restore(&meta.id, &cfg).is_err());
        assert!(!path.exists() && quarantine::load_meta(&meta.id, &cfg).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
