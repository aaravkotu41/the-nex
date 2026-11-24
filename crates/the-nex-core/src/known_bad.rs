//! Known-malware list: SHA-256 prefixes of files already identified as malware. Unlike the AI
//! and the command-line patterns, a match here is not a guess, so it is acted on at once.
//!
//! The list is one file built by `scripts/fetch_hash_list.py` (little-endian):
//!   0..8    magic `NEXKB\x01\0\0`
//!   8..16   entry count N
//!   16..24  created, Unix seconds UTC
//!   24..56  SHA-256 of the body
//!   56..    N x 16 bytes: the first 16 bytes of each file's SHA-256, ascending, no duplicates
//! 16 of the 32 bytes keep a million entries at 16 MB; a clean file sharing a 128-bit prefix
//! with one of them by chance is about 1 in 10^32.
//!
//! The file is memory-mapped and binary-searched, so it costs a few touched pages per lookup
//! rather than 16 MB of heap. It is refused whole if anything about it is off: a damaged or
//! swapped list could make The Nex quarantine arbitrary files.

use crate::ai_policy::{self, Action, Request, Target};
use crate::bin_ai;
use crate::config::AppConfig;
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use chrono::{DateTime, TimeZone, Utc};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

pub const FILE_NAME: &str = "known_bad.bin";
pub const THREAT_TYPE: &str = "KNOWN_MALWARE";
/// Larger files are not hashed: reading them would stall scanning for little gain (samples this
/// big are rare). A deliberate limit, stated in README.
pub const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

const MAGIC: [u8; 8] = *b"NEXKB\x01\0\0";
const HEADER_LEN: usize = 56;
const PREFIX_LEN: usize = 16;
const READ_CHUNK: usize = 256 * 1024;

/// Body checksum of the list this build was made with, or `none`. The installed service loads
/// only that exact list (see `load_shipped`); `scripts/fetch_hash_list.py --pin` rewrites it.
const SHIPPED_CHECKSUM: &str = include_str!("../known_bad.sha256");

pub type Digest32 = [u8; 32];

/// False for a build made without a list (the committed state until a real list is licensed).
pub fn ships_list() -> bool {
    let pin = SHIPPED_CHECKSUM.trim();
    !pin.is_empty() && !pin.eq_ignore_ascii_case("none")
}

pub struct KnownBad {
    /// The mapped file; `None` for the empty list.
    map: Option<Mmap>,
    count: usize,
    created: u64,
    checksum: Digest32,
}

impl fmt::Debug for KnownBad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnownBad({} entries)", self.count)
    }
}

impl Default for KnownBad {
    fn default() -> Self {
        Self::empty()
    }
}

impl KnownBad {
    /// No list: every lookup misses.
    pub fn empty() -> Self {
        Self {
            map: None,
            count: 0,
            created: 0,
            checksum: [0; 32],
        }
    }

    /// Loads and fully verifies a list file: magic, exact length, body checksum and strict
    /// ascending order. Anything else is an error; a partly trusted list is never used.
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = quarantine::open_nofollow(path).map_err(|e| e.to_string())?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        if len < HEADER_LEN as u64 {
            return Err("too short to be a list".to_string());
        }
        // SAFETY: the mapping is read-only and every access below is bounds-checked against
        // `map.len()`. The file sits in a folder only the service's owner can write; if it is
        // truncated underneath a running service the OS faults the process, which the service
        // manager restarts, and the restarted service then refuses the damaged file.
        let map = unsafe { Mmap::map(&file) }.map_err(|e| e.to_string())?;
        if map.len() as u64 != len || map[..8] != MAGIC {
            return Err("not a known-malware list (bad header)".to_string());
        }
        let field = |at: usize| u64::from_le_bytes(map[at..at + 8].try_into().unwrap_or([0; 8]));
        let (count, created) = (field(8), field(16));
        let expected_len = (count as u128) * PREFIX_LEN as u128 + HEADER_LEN as u128;
        if expected_len != len as u128 {
            return Err(format!(
                "length {len} does not match its entry count {count}"
            ));
        }
        let body = &map[HEADER_LEN..];
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&map[24..HEADER_LEN]);
        if Sha256::digest(body).as_slice() != checksum {
            return Err("checksum mismatch: the list is damaged or was altered".to_string());
        }
        // A binary search over unsorted data would silently miss entries.
        let (entries, _) = body.as_chunks::<PREFIX_LEN>();
        if entries.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("entries are not in strictly ascending order".to_string());
        }
        Ok(Self {
            map: Some(map),
            count: count as usize,
            created,
            checksum,
        })
    }

    /// The list a service build may load from its data folder: only the exact file this build
    /// was made with. A build made without one accepts none, so a list dropped next to the
    /// service later cannot steer what it quarantines.
    pub fn load_shipped(path: &Path) -> Result<Self, String> {
        let expected = SHIPPED_CHECKSUM.trim();
        if !ships_list() {
            return Err("this build ships without a known-malware list".to_string());
        }
        let list = Self::load(path)?;
        if !quarantine::to_hex(&list.checksum).eq_ignore_ascii_case(expected) {
            return Err("not the list this build was made with".to_string());
        }
        Ok(list)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn created(&self) -> Option<DateTime<Utc>> {
        (self.count > 0)
            .then(|| Utc.timestamp_opt(self.created as i64, 0).single())
            .flatten()
    }

    /// True when the file with this SHA-256 is on the list.
    pub fn contains(&self, digest: &Digest32) -> bool {
        let Some(map) = &self.map else {
            return false;
        };
        let (entries, _) = map[HEADER_LEN..].as_chunks::<PREFIX_LEN>();
        let (want, _) = digest.split_at(PREFIX_LEN);
        entries
            .binary_search_by(|entry| entry.as_slice().cmp(want))
            .is_ok()
    }

    /// "list of 2026-11-18, 1000000 entries"
    pub fn summary(&self) -> String {
        let dated = self
            .created()
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "unknown date".to_string());
        format!("list of {dated}, {} entries", self.count)
    }

    /// The plain-words reason attached to every match.
    pub fn describe(&self, digest: &Digest32) -> String {
        format!(
            "matched known-malware list ({}) sha256={}",
            self.summary(),
            quarantine::to_hex(digest)
        )
    }
}

/// SHA-256 of a regular file of at most `max_bytes`. `None` when it is larger, is not a regular
/// file (links are never followed), cannot be read, or grows past the limit while being read.
pub fn hash_file(path: &Path, max_bytes: u64) -> Option<Digest32> {
    let mut file = quarantine::open_nofollow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; READ_CHUNK];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_bytes {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hasher.finalize().into())
}

/// Identity of a file's content for caching a verdict per program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamp {
    /// Inode, size, mtime and ctime: an overwrite cannot keep this stamp.
    Strong(bin_ai::FileStamp),
    /// shortcut: size and modified time only, where the OS gives no tamper-resistant stamp
    /// (Windows). Both can be forged, so callers may remember "not on the list" under a weak
    /// stamp but never a match (it could be acted on against a different file). A listed file
    /// swapped in with the same size and time goes unnoticed until the service restarts;
    /// replace with volume serial + file index + change time to close that.
    Weak { len: u64, modified_ns: u128 },
}

pub fn stamp(meta: &fs::Metadata) -> Option<Stamp> {
    if let Some(strong) = bin_ai::file_stamp(meta) {
        return Some(Stamp::Strong(strong));
    }
    let modified = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(Stamp::Weak {
        len: meta.len(),
        modified_ns: modified.as_nanos(),
    })
}

/// File types the list holds: programs and archives (by content), scripts and documents (by
/// name). A full scan hashes only these; hashing every file on a disk would take hours.
pub fn is_listed_type(path: &Path, is_program_or_archive: bool) -> bool {
    const LISTED_EXTENSIONS: &[&str] = &[
        "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "bat", "cmd", "lnk", "sh",
        "command", "py", "jar", "msi", "iso", "img", "dmg", "pkg", "doc", "docx", "docm", "xls",
        "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf", "pdf",
    ];
    is_program_or_archive
        || path.extension().is_some_and(|ext| {
            let ext = ext.to_string_lossy().to_ascii_lowercase();
            LISTED_EXTENSIONS.contains(&ext.as_str())
        })
}

/// What to do about a match. The same guardrails as the AI's verdicts (`ai_policy::decide`),
/// with the match treated as full confidence: dry run only reports; OS-critical paths and The
/// Nex's own files are alert-only; a program that was already running when protection started
/// is never stopped. One addition: a file the OS vendor itself signed is alert-only, because a
/// wrong list entry that quarantined a system component would break the machine.
pub fn decide(cfg: &AppConfig, path: &Path, target: Target, details: &str) -> Action {
    if platform::is_os_vendor_signed(path) {
        return Action::Alert("signed by the operating system vendor; alert only");
    }
    ai_policy::decide(&Request {
        path,
        score: 1.0,
        threshold: cfg.ai_threshold,
        trusted: false,
        dry_run: cfg.is_dry_run(),
        target,
        explanation: details,
        data_dir: &cfg.base_dir,
    })
}

/// Looks one file up and, on a match, responds (quarantine unless a guardrail or dry run says
/// otherwise) and logs a critical event. Returns the reason text when the file matched.
pub fn check_file(cfg: &AppConfig, path: &Path) -> Option<String> {
    let digest = hash_file(path, MAX_HASH_BYTES)?;
    if !cfg.known_bad.contains(&digest) {
        return None;
    }
    let details = cfg.known_bad.describe(&digest);
    let action = match decide(cfg, path, Target::File, &details) {
        Action::Quarantine => match quarantine::quarantine_file(path, cfg, THREAT_TYPE, &details) {
            Ok(meta) => format!("QUARANTINED id={}", meta.id),
            Err(e) => format!("QUARANTINE_FAILED: {e}"),
        },
        Action::WouldQuarantine => "DRY_RUN: would quarantine".to_string(),
        Action::Alert(why) => format!("ALERT_ONLY: {why}"),
        // Not reachable for a file at full confidence; never act on an unexpected verdict.
        other => format!("ALERT_ONLY: no action taken ({other:?})"),
    };
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            THREAT_TYPE,
            Severity::Critical,
            path.display().to_string(),
            action,
            details.clone(),
        ),
    );
    Some(details)
}

/// Test and tooling helper: writes a list in the on-disk format (the Python builder's twin).
pub fn write_list(path: &Path, digests: &[Digest32], created: u64) -> std::io::Result<()> {
    let mut prefixes: Vec<[u8; PREFIX_LEN]> = digests
        .iter()
        .map(|d| {
            let mut p = [0u8; PREFIX_LEN];
            p.copy_from_slice(&d[..PREFIX_LEN]);
            p
        })
        .collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    let body: Vec<u8> = prefixes.concat();
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(prefixes.len() as u64).to_le_bytes());
    out.extend_from_slice(&created.to_le_bytes());
    out.extend_from_slice(Sha256::digest(&body).as_slice());
    out.extend_from_slice(&body);
    fs::write(path, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-kb-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn digest_of(text: &str) -> Digest32 {
        Sha256::digest(text.as_bytes()).into()
    }

    #[test]
    fn finds_listed_hashes_and_nothing_else() {
        let dir = temp("lookup");
        let path = dir.join(FILE_NAME);
        let listed: Vec<Digest32> = (0..500).map(|i| digest_of(&format!("bad-{i}"))).collect();
        // Duplicates and input order must not matter.
        let mut input = listed.clone();
        input.extend_from_slice(&listed[..50]);
        input.reverse();
        write_list(&path, &input, 1_795_000_000).unwrap();

        let list = KnownBad::load(&path).unwrap();
        assert_eq!(list.len(), 500);
        assert_eq!(
            list.created().unwrap().format("%Y-%m-%d").to_string(),
            "2026-11-18"
        );
        for digest in &listed {
            assert!(list.contains(digest));
        }
        for i in 0..500 {
            assert!(!list.contains(&digest_of(&format!("clean-{i}"))));
        }
        // First and last entries are the binary search's edge cases.
        let mut sorted = listed.clone();
        sorted.sort_unstable();
        assert!(list.contains(&sorted[0]) && list.contains(&sorted[499]));
        // Only the first 16 bytes are stored: the tail of the digest is not compared.
        let mut same_prefix = sorted[7];
        same_prefix[31] ^= 0xFF;
        assert!(list.contains(&same_prefix));
        let mut other_prefix = sorted[7];
        other_prefix[15] ^= 0x01;
        assert!(!list.contains(&other_prefix));
        assert!(list
            .describe(&sorted[0])
            .starts_with("matched known-malware list (list of 2026-11-18, 500 entries) sha256="));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_list_is_valid_and_matches_nothing() {
        let dir = temp("empty");
        let path = dir.join(FILE_NAME);
        write_list(&path, &[], 1).unwrap();
        let list = KnownBad::load(&path).unwrap();
        assert!(list.is_empty() && list.created().is_none());
        assert!(!list.contains(&digest_of("anything")));
        assert!(!KnownBad::empty().contains(&digest_of("anything")));
        assert!(KnownBad::load(&dir.join("missing.bin")).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_lists_are_refused_whole() {
        let dir = temp("corrupt");
        let path = dir.join(FILE_NAME);
        let digests: Vec<Digest32> = (0..64).map(|i| digest_of(&format!("bad-{i}"))).collect();
        write_list(&path, &digests, 5).unwrap();
        let good = fs::read(&path).unwrap();
        let refused = |bytes: &[u8], why: &str| {
            fs::write(&path, bytes).unwrap();
            let err = KnownBad::load(&path).expect_err(why);
            assert!(!err.is_empty(), "{why}");
        };

        let mut flipped = good.clone();
        flipped[HEADER_LEN + 40] ^= 0x01;
        refused(&flipped, "one flipped bit in the body");
        refused(&good[..good.len() - 1], "truncated by a byte");
        refused(&good[..good.len() - PREFIX_LEN], "a whole entry missing");
        refused(&good[..20], "shorter than the header");
        let mut extra = good.clone();
        extra.extend_from_slice(&[0u8; PREFIX_LEN]);
        refused(&extra, "an entry appended without updating the header");
        let mut magic = good.clone();
        magic[0] = b'X';
        refused(&magic, "wrong magic");
        let mut count = good.clone();
        count[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        refused(&count, "absurd entry count");

        // Unsorted body with a checksum that matches it: only the order check can catch this.
        let mut body = good[HEADER_LEN..].to_vec();
        let (first, rest) = body.split_at_mut(PREFIX_LEN);
        first.swap_with_slice(&mut rest[..PREFIX_LEN]);
        let mut unsorted = good[..24].to_vec();
        unsorted.extend_from_slice(Sha256::digest(&body).as_slice());
        unsorted.extend_from_slice(&body);
        refused(&unsorted, "entries out of order");

        fs::write(&path, &good).unwrap();
        assert_eq!(KnownBad::load(&path).unwrap().len(), 64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_build_without_a_shipped_list_accepts_none() {
        // The committed pin is `none`; a real one is 64 hex characters.
        let pin = SHIPPED_CHECKSUM.trim();
        assert!(pin.eq_ignore_ascii_case("none") || pin.len() == 64, "{pin}");
        if pin.eq_ignore_ascii_case("none") {
            let dir = temp("shipped");
            let path = dir.join(FILE_NAME);
            write_list(&path, &[digest_of("bad")], 5).unwrap();
            assert!(KnownBad::load(&path).is_ok());
            assert!(KnownBad::load_shipped(&path).is_err());
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn hashing_respects_the_size_cap_and_never_follows_links() {
        let dir = temp("hash");
        let file = dir.join("sample.bin");
        fs::write(&file, b"harmless sample").unwrap();
        assert_eq!(
            hash_file(&file, 1024).unwrap(),
            digest_of("harmless sample")
        );
        assert!(hash_file(&file, 4).is_none(), "over the cap");
        assert!(hash_file(&dir, 1024).is_none(), "a folder");
        assert!(hash_file(&dir.join("missing"), 1024).is_none());
        #[cfg(unix)]
        {
            let link = dir.join("link.bin");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(hash_file(&link, 1024).is_none(), "a symlink");
        }
        let before = stamp(&fs::metadata(&file).unwrap()).unwrap();
        assert_eq!(before, stamp(&fs::metadata(&file).unwrap()).unwrap());
        fs::write(&file, b"harmless sample, changed").unwrap();
        assert_ne!(before, stamp(&fs::metadata(&file).unwrap()).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn listed_types_cover_scripts_and_documents_by_name() {
        for name in ["a.ps1", "b.VBS", "c.docm", "d.hta", "e.pdf", "f.jar"] {
            assert!(is_listed_type(Path::new(name), false), "{name}");
        }
        for name in ["notes.txt", "photo.jpg", "movie.mp4", "noext"] {
            assert!(!is_listed_type(Path::new(name), false), "{name}");
        }
        assert!(is_listed_type(Path::new("anything.dat"), true));
    }
}
