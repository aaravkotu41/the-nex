use crate::config::AppConfig;
use crate::logger::{self, lock_or_recover};
use crate::platform;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

fn meta_path(cfg: &AppConfig, id: &str) -> PathBuf {
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

pub fn restore_file(id: &str, cfg: &AppConfig) -> io::Result<QuarantineMeta> {
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
        fs::create_dir_all(parent)?;
    }
    if let Err(e) = move_file(&meta.quarantined_path, &meta.original_path) {
        relock();
        return Err(e);
    }
    // A same-volume rename keeps the quarantine ACL; re-inherit from the destination folder.
    platform::unlock_restored_file(&meta.original_path);
    fs::remove_file(&meta_file)?;
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

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// FIPS 180-4 SHA-256 (kept in-tree to avoid an extra dependency).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buffer_len > 0 {
            let take = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffer_len = rest.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        let zeros = if self.buffer_len < 56 {
            55 - self.buffer_len
        } else {
            119 - self.buffer_len
        };
        let mut tail = Vec::with_capacity(1 + zeros + 8);
        tail.push(0x80);
        tail.resize(1 + zeros, 0);
        tail.extend_from_slice(&bit_len.to_be_bytes());
        self.update(&tail);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for (k, wi) in SHA256_K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*k)
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        to_hex(&h.finalize())
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut streaming = Sha256::new();
        for chunk in data.chunks(97) {
            streaming.update(chunk);
        }
        assert_eq!(to_hex(&streaming.finalize()), hash(&data));
    }

    #[test]
    fn id_validation() {
        assert!(is_valid_id(&new_id()));
        assert!(!is_valid_id("../evil"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("a b"));
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let root =
            std::env::temp_dir().join(format!("thenex-quarantine-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
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
        assert!(meta
            .quarantined_path
            .to_string_lossy()
            .ends_with(".quarantined"));

        let restored = restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(restored.original_path, meta.original_path);
        assert_eq!(fs::read(&victim).unwrap(), b"MZ payload");
        assert!(!meta.quarantined_path.exists());
        assert!(!meta_path(&cfg, &meta.id).exists());
        assert!(restore_file(&meta.id, &cfg).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_rejects_path_traversal_ids() {
        let cfg = AppConfig::for_base_dir(&std::env::temp_dir().join("thenex-none"));
        let err = restore_file("..\\..\\x", &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn event_round_trips_through_json() {
        let event = ThreatEvent::new("ZIP_BOMB", Severity::High, "x.zip", "QUARANTINED", "ratio");
        let line = serde_json::to_string(&event).unwrap();
        assert!(line.contains("\"severity\":\"HIGH\""));
        let back: ThreatEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(back, event);
    }
}
