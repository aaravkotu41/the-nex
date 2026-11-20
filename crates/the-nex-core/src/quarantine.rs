use crate::config::AppConfig;
use crate::logger::{self, lock_or_recover};
use crate::platform;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

const MAX_EVENTS_BYTES: u64 = 50 * 1024 * 1024;
const MOVE_ATTEMPTS: u32 = 8;
const MOVE_RETRY_DELAY: Duration = Duration::from_millis(250);
const META_SUFFIX: &str = ".meta.json";
const QUARANTINE_SUFFIX: &str = ".quarantined";
const MAX_ID_LEN: usize = 64;

static EVENT_LOG_LOCK: Mutex<()> = Mutex::new(());
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static THREAT_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub threat_type: String,
    pub severity: Severity,
    pub target: String,
    pub action_taken: String,
    pub details: String,
}

impl ThreatEvent {
    pub fn new(
        threat_type: &str,
        severity: Severity,
        target: impl Into<String>,
        action_taken: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            id: new_id(),
            timestamp: Utc::now(),
            threat_type: threat_type.to_string(),
            severity,
            target: target.into(),
            action_taken: action_taken.into(),
            details: details.into(),
        }
    }

    /// Quarantine ID recorded in `action_taken` ("QUARANTINED id=<ID>"), if any.
    pub fn quarantine_id(&self) -> Option<&str> {
        let rest = self.action_taken.split("id=").nth(1)?;
        let id = rest.split(|c: char| c.is_whitespace() || c == ';').next()?;
        is_valid_id(id).then_some(id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineMeta {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub threat_type: String,
    pub details: String,
    pub quarantined_at: DateTime<Utc>,
}

pub fn new_id() -> String {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed) % 10_000;
    format!(
        "{}-{:x}-{n:04}",
        Utc::now().format("%Y%m%d%H%M%S%3f"),
        std::process::id()
    )
}

pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

pub fn notification_title(event: &ThreatEvent) -> String {
    format!(
        "The Nex: {} ({})",
        event.threat_type,
        event.severity.as_str()
    )
}

pub fn notification_body(event: &ThreatEvent) -> String {
    format!(
        "{}\n{}",
        truncate_chars(&event.target, 120),
        truncate_chars(&event.action_taken, 120)
    )
}

/// Threat events (severity above LOW) recorded by this process.
pub fn threat_events_recorded() -> u64 {
    THREAT_EVENTS.load(Ordering::Relaxed)
}

/// Appends one JSON line; a single write on an O_APPEND handle keeps lines whole.
pub fn append_event(cfg: &AppConfig, event: &ThreatEvent) -> io::Result<()> {
    let _guard = lock_or_recover(&EVENT_LOG_LOCK);
    if let Some(parent) = cfg.events_log.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_events_if_needed(&cfg.events_log);
    let mut line = serde_json::to_string(event).map_err(io::Error::other)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.events_log)?;
    file.write_all(line.as_bytes())?;
    file.flush()
}

pub fn record_event(cfg: &AppConfig, event: ThreatEvent) {
    let summary = format!(
        "{} [{}] target={} action={} details={}",
        event.threat_type,
        event.severity.as_str(),
        event.target,
        event.action_taken,
        event.details
    );
    if event.severity == Severity::Low {
        logger::info(summary);
    } else {
        THREAT_EVENTS.fetch_add(1, Ordering::Relaxed);
        logger::warn(summary);
    }
    if let Err(e) = append_event(cfg, &event) {
        logger::error(format!(
            "cannot append event to {}: {e}",
            cfg.events_log.display()
        ));
    }
    if cfg.interactive {
        platform::send_desktop_notification(
            &notification_title(&event),
            &notification_body(&event),
        );
    }
}

fn rotate_events_if_needed(path: &Path) {
    if fs::metadata(path)
        .map(|m| m.len() >= MAX_EVENTS_BYTES)
        .unwrap_or(false)
    {
        let rotated = path.with_extension("jsonl.1");
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(path, &rotated);
    }
}

/// Newest-first events from the log, reading at most the trailing `max_bytes`.
pub fn read_recent_events(path: &Path, max_bytes: u64) -> io::Result<Vec<ThreatEvent>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    let mut buffer = Vec::with_capacity((len - start) as usize);
    io::Seek::seek(&mut file, io::SeekFrom::Start(start))?;
    file.read_to_end(&mut buffer)?;
    let text = String::from_utf8_lossy(&buffer);
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    let mut events: Vec<ThreatEvent> = lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    events.reverse();
    Ok(events)
}

pub fn set_readonly(path: &Path, readonly: bool) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    if permissions.readonly() != readonly {
        permissions.set_readonly(readonly);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

/// Rename first; fall back to copy + delete for cross-volume moves. Retries cover
/// transient sharing violations (scanners, a just-terminated process image).
pub fn move_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut last_error = io::Error::other("move not attempted");
    for attempt in 0..MOVE_ATTEMPTS {
        match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(e) => last_error = e,
        }
        match fs::copy(src, dst) {
            Ok(_) => {
                let _ = set_readonly(src, false);
                match fs::remove_file(src) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let _ = set_readonly(dst, false);
                        let _ = fs::remove_file(dst);
                        last_error = e;
                    }
                }
            }
            Err(e) => {
                if dst.exists() {
                    let _ = fs::remove_file(dst);
                }
                last_error = e;
            }
        }
        if attempt + 1 < MOVE_ATTEMPTS {
            thread::sleep(MOVE_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn sanitize_file_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

pub fn meta_path(cfg: &AppConfig, id: &str) -> PathBuf {
    cfg.quarantine_dir.join(format!("{id}{META_SUFFIX}"))
}

fn write_meta(cfg: &AppConfig, meta: &QuarantineMeta) -> io::Result<()> {
    let target = meta_path(cfg, &meta.id);
    let staging = target.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    fs::write(&staging, body)?;
    fs::rename(&staging, &target)
}

pub fn quarantine_file(
    path: &Path,
    cfg: &AppConfig,
    threat_type: &str,
    details: &str,
) -> io::Result<QuarantineMeta> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    fs::create_dir_all(&cfg.quarantine_dir)?;
    let original_path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let sha256 = sha256_file(path)?;
    let id = new_id();
    let quarantined_path = cfg.quarantine_dir.join(format!(
        "{id}_{}{QUARANTINE_SUFFIX}",
        sanitize_file_name(path)
    ));

    move_file(&original_path, &quarantined_path)?;
    platform::lock_quarantined_file(&quarantined_path);

    let meta = QuarantineMeta {
        id,
        original_path,
        quarantined_path,
        sha256,
        size: metadata.len(),
        threat_type: threat_type.to_string(),
        details: details.to_string(),
        quarantined_at: Utc::now(),
    };
    if let Err(e) = write_meta(cfg, &meta) {
        platform::unlock_restored_file(&meta.quarantined_path);
        let _ = move_file(&meta.quarantined_path, &meta.original_path);
        return Err(e);
    }
    Ok(meta)
}

/// Reads and validates a quarantine record; the stored path must stay inside the quarantine folder.
pub fn load_meta(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    if !is_valid_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid quarantine ID: {id}"),
        ));
    }
    let meta_file = meta_path(cfg, id);
    let raw = fs::read(&meta_file)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", meta_file.display())))?;
    let meta: QuarantineMeta =
        serde_json::from_slice(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if meta.id != id || !platform::path_is_within(&meta.quarantined_path, &cfg.quarantine_dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine metadata does not match its ID or location",
        ));
    }
    Ok(meta)
}

/// Every quarantine record, newest first.
pub fn list_quarantined(cfg: &AppConfig) -> io::Result<Vec<QuarantineMeta>> {
    let mut records = Vec::new();
    for entry in fs::read_dir(&cfg.quarantine_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(META_SUFFIX) else {
            continue;
        };
        if let Ok(meta) = load_meta(id, cfg) {
            records.push(meta);
        }
    }
    records.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
    Ok(records)
}

pub fn restore_file(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    let meta = load_meta(id, cfg)?;
    if meta.original_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; move it away before restoring",
                meta.original_path.display()
            ),
        ));
    }

    platform::unlock_restored_file(&meta.quarantined_path);
    let relock = || platform::lock_quarantined_file(&meta.quarantined_path);

    let actual = match sha256_file(&meta.quarantined_path) {
        Ok(hash) => hash,
        Err(e) => {
            relock();
            return Err(e);
        }
    };
    if actual != meta.sha256 {
        relock();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SHA-256 mismatch for {}: expected {}, found {actual}",
                meta.quarantined_path.display(),
                meta.sha256
            ),
        ));
    }
    if let Some(parent) = meta.original_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            relock();
            return Err(e);
        }
    }
    if let Err(e) = move_file(&meta.quarantined_path, &meta.original_path) {
        relock();
        return Err(e);
    }
    // A same-volume rename keeps the quarantine ACL; re-inherit from the destination folder.
    platform::unlock_restored_file(&meta.original_path);
    fs::remove_file(meta_path(cfg, id))?;
    Ok(meta)
}

/// Permanently removes a quarantined file and its record.
pub fn delete_quarantined_file(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
    let meta = load_meta(id, cfg)?;
    if meta.quarantined_path.exists() {
        platform::unlock_restored_file(&meta.quarantined_path);
        fs::remove_file(&meta.quarantined_path)?;
    }
    fs::remove_file(meta_path(cfg, id))?;
    Ok(meta)
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("thenex-q-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn id_validation_and_extraction() {
        assert!(is_valid_id(&new_id()));
        assert!(!is_valid_id("../evil"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("a b"));
        let event = ThreatEvent::new("ZIP_BOMB", Severity::High, "x", "QUARANTINED id=abc-12", "");
        assert_eq!(event.quarantine_id(), Some("abc-12"));
        let event = ThreatEvent::new(
            "X",
            Severity::High,
            "x",
            "TERMINATED 1; QUARANTINED id=z_9",
            "",
        );
        assert_eq!(event.quarantine_id(), Some("z_9"));
        let event = ThreatEvent::new("X", Severity::High, "x", "DRY_RUN", "");
        assert_eq!(event.quarantine_id(), None);
    }

    #[test]
    fn quarantine_list_restore_and_delete() {
        let root = temp_root("roundtrip");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let victim = root.join("victim.exe");
        fs::write(&victim, b"MZ payload").unwrap();
        let expected = sha256_file(&victim).unwrap();

        let meta = quarantine_file(&victim, &cfg, "TEST", "unit test").unwrap();
        assert!(!victim.exists());
        assert!(meta.quarantined_path.exists());
        assert!(meta_path(&cfg, &meta.id).exists());
        assert_eq!(meta.sha256, expected);
        assert_eq!(list_quarantined(&cfg).unwrap(), vec![meta.clone()]);

        restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"MZ payload");
        assert!(list_quarantined(&cfg).unwrap().is_empty());

        let again = quarantine_file(&victim, &cfg, "TEST", "unit test").unwrap();
        delete_quarantined_file(&again.id, &cfg).unwrap();
        assert!(!again.quarantined_path.exists());
        assert!(!victim.exists());
        assert!(list_quarantined(&cfg).unwrap().is_empty());
        assert!(delete_quarantined_file(&again.id, &cfg).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn recent_events_are_newest_first() {
        let root = temp_root("events");
        let cfg = AppConfig::for_base_dir(&root);
        for kind in ["A", "B", "C"] {
            append_event(&cfg, &ThreatEvent::new(kind, Severity::High, "t", "a", "d")).unwrap();
        }
        let events = read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        let kinds: Vec<&str> = events.iter().map(|e| e.threat_type.as_str()).collect();
        assert_eq!(kinds, ["C", "B", "A"]);
        let tail = read_recent_events(&cfg.events_log, 400).unwrap();
        assert!(tail.len() < 3 && tail[0].threat_type == "C");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_rejects_path_traversal_ids() {
        let cfg = AppConfig::for_base_dir(&std::env::temp_dir().join("thenex-none"));
        let err = restore_file("..\\..\\x", &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
