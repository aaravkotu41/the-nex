use crate::config::{AppConfig, ZipLimits};
use crate::quarantine::{self, Severity, ThreatEvent};
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::thread;
use std::time::Duration;
use zip::result::ZipResult;
use zip::ZipArchive;

const IGNORED_EXTENSIONS: &[&str] = &[
    "crdownload",
    "part",
    "partial",
    "download",
    "opdownload",
    "tmp",
    "quarantined",
];
const READY_POLL: Duration = Duration::from_millis(150);
const READY_MAX_RETRIES: u32 = 5;
const READY_STABLE_CHECKS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipThreatKind {
    CompressionRatio,
    UncompressedSize,
    OverlappingEntries,
    NestingDepth,
    NestedSizeMismatch,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ZipThreat {
    pub kind: ZipThreatKind,
    pub depth: u32,
    pub entries: usize,
    pub total_compressed: u64,
    pub total_uncompressed: u64,
    pub detail: String,
}

impl ZipThreat {
    pub fn summary(&self) -> String {
        format!(
            "{:?} at depth {}: {} (entries={}, compressed={} B, uncompressed={} B)",
            self.kind,
            self.depth,
            self.detail,
            self.entries,
            self.total_compressed,
            self.total_uncompressed
        )
    }
}

pub fn is_ignored_extension(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|ext| IGNORED_EXTENSIONS.contains(&ext.as_str()))
}

/// True once the size is unchanged across two consecutive 150 ms checks and the file opens.
pub fn wait_for_file_ready(path: &Path) -> bool {
    if is_ignored_extension(path) {
        return false;
    }
    let mut previous = match fs::metadata(path) {
        Ok(m) if m.is_file() => m.len(),
        _ => return false,
    };
    let mut stable = 0;
    for _ in 0..(READY_STABLE_CHECKS + READY_MAX_RETRIES) {
        thread::sleep(READY_POLL);
        let current = match fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => return false,
        };
        if current == previous {
            stable += 1;
            if stable >= READY_STABLE_CHECKS && File::open(path).is_ok() {
                return true;
            }
        } else {
            stable = 0;
            previous = current;
        }
    }
    false
}

/// Reads only the central directory and (bounded, in-memory) nested archives; never extracts.
pub fn inspect_zip_file(path: &Path, cfg: &AppConfig) -> Option<ZipThreat> {
    let file = File::open(path).ok()?;
    let mut budget = 0u64;
    match inspect_zip_reader(BufReader::new(file), 1, &cfg.zip_limits, &mut budget) {
        Ok(result) => result,
        Err(_) => raw_overlap_scan(BufReader::new(File::open(path).ok()?), 1),
    }
}

pub fn inspect_zip_bytes(bytes: &[u8], limits: &ZipLimits) -> Option<ZipThreat> {
    let mut budget = 0u64;
    match inspect_zip_reader(Cursor::new(bytes), 1, limits, &mut budget) {
        Ok(result) => result,
        Err(_) => raw_overlap_scan(Cursor::new(bytes), 1),
    }
}

fn le_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

fn le_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Minimal central-directory walk used when the zip crate refuses an archive, so that
/// overlapping-entry bombs other extractors would still expand are flagged anyway.
fn raw_overlap_scan<R: Read + Seek>(mut reader: R, depth: u32) -> Option<ZipThreat> {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CDFH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;
    const MAX_CD_BYTES: u64 = 64 * 1024 * 1024;

    let len = reader.seek(SeekFrom::End(0)).ok()?;
    let tail_len = len.min(MAX_EOCD_SEARCH);
    reader.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    reader.read_exact(&mut tail).ok()?;
    let eocd = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| tail[i..i + 4] == EOCD_SIG)?;
    let entries = le_u16(&tail, eocd + 10) as usize;
    let cd_size = le_u32(&tail, eocd + 12) as u64;
    let cd_offset = le_u32(&tail, eocd + 16) as u64;
    if cd_size > MAX_CD_BYTES || cd_offset.checked_add(cd_size)? > len {
        return None;
    }

    reader.seek(SeekFrom::Start(cd_offset)).ok()?;
    let mut cd = vec![0u8; cd_size as usize];
    reader.read_exact(&mut cd).ok()?;

    let mut records: Vec<(u64, u64)> = Vec::with_capacity(entries.min(65_535));
    let mut pos = 0usize;
    while records.len() < entries && pos + 46 <= cd.len() && cd[pos..pos + 4] == CDFH_SIG {
        let compressed = le_u32(&cd, pos + 20) as u64;
        let name_len = le_u16(&cd, pos + 28) as usize;
        let extra_len = le_u16(&cd, pos + 30) as usize;
        let comment_len = le_u16(&cd, pos + 32) as usize;
        let local_offset = le_u32(&cd, pos + 42) as u64;
        records.push((local_offset, compressed));
        pos += 46 + name_len + extra_len + comment_len;
    }

    let total_compressed = records.iter().map(|r| r.1).fold(0u64, u64::saturating_add);
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(records.len());
    for (offset, compressed) in &records {
        if *compressed == 0 || reader.seek(SeekFrom::Start(*offset)).is_err() {
            continue;
        }
        let mut header = [0u8; 30];
        if reader.read_exact(&mut header).is_err() || header[..4] != LFH_SIG {
            continue;
        }
        let start = offset + 30 + le_u16(&header, 26) as u64 + le_u16(&header, 28) as u64;
        spans.push((start, start.saturating_add(*compressed)));
    }
    spans.sort_unstable();
    let pair = spans.windows(2).find(|pair| pair[1].0 < pair[0].1)?;
    Some(ZipThreat {
        kind: ZipThreatKind::OverlappingEntries,
        depth,
        entries: records.len(),
        total_compressed,
        total_uncompressed: 0,
        detail: format!(
            "entry data at offset {} overlaps entry data spanning {}..{} (raw central directory scan)",
            pair[1].0, pair[0].0, pair[0].1
        ),
    })
}

fn inspect_zip_reader<R: Read + Seek>(
    reader: R,
    depth: u32,
    limits: &ZipLimits,
    budget: &mut u64,
) -> ZipResult<Option<ZipThreat>> {
    let mut archive = ZipArchive::new(reader)?;
    let entries = archive.len();
    if depth > limits.max_depth {
        return Ok(Some(ZipThreat {
            kind: ZipThreatKind::NestingDepth,
            depth,
            entries,
            total_compressed: 0,
            total_uncompressed: 0,
            detail: format!(
                "archive nested {depth} levels deep exceeds the limit of {}",
                limits.max_depth
            ),
        }));
    }

    let mut total_compressed = 0u64;
    let mut total_uncompressed = 0u64;
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(entries);
    let mut nested: Vec<usize> = Vec::new();

    for index in 0..entries {
        let Ok(entry) = archive.by_index_raw(index) else {
            continue;
        };
        let compressed = entry.compressed_size();
        let uncompressed = entry.size();
        total_compressed = total_compressed.saturating_add(compressed);
        total_uncompressed = total_uncompressed.saturating_add(uncompressed);
        if compressed > 0 {
            let start = entry.data_start();
            spans.push((start, start.saturating_add(compressed)));
        }
        if !entry.is_dir()
            && entry.name().to_ascii_lowercase().ends_with(".zip")
            && uncompressed <= limits.max_nested_mem_read
        {
            nested.push(index);
        }
    }
    *budget = budget.saturating_add(total_uncompressed);

    let threat = |kind: ZipThreatKind, detail: String| ZipThreat {
        kind,
        depth,
        entries,
        total_compressed,
        total_uncompressed,
        detail,
    };

    if total_uncompressed > limits.max_uncompressed_bytes || *budget > limits.max_uncompressed_bytes
    {
        return Ok(Some(threat(
            ZipThreatKind::UncompressedSize,
            format!(
                "declared uncompressed size {} B (cumulative {} B) exceeds {} B",
                total_uncompressed, *budget, limits.max_uncompressed_bytes
            ),
        )));
    }

    let ratio = total_uncompressed as f64 / total_compressed.max(1) as f64;
    if ratio > limits.max_ratio && total_uncompressed >= limits.min_ratio_check_bytes {
        return Ok(Some(threat(
            ZipThreatKind::CompressionRatio,
            format!(
                "compression ratio {ratio:.1}:1 exceeds {:.0}:1",
                limits.max_ratio
            ),
        )));
    }

    spans.sort_unstable();
    if let Some(pair) = spans.windows(2).find(|pair| pair[1].0 < pair[0].1) {
        return Ok(Some(threat(
            ZipThreatKind::OverlappingEntries,
            format!(
                "entry data at offset {} overlaps entry data spanning {}..{}",
                pair[1].0, pair[0].0, pair[0].1
            ),
        )));
    }

    for index in nested {
        let mut data = Vec::new();
        {
            let Ok(entry) = archive.by_index(index) else {
                continue;
            };
            if entry
                .take(limits.max_nested_mem_read + 1)
                .read_to_end(&mut data)
                .is_err()
            {
                continue;
            }
        }
        if data.len() as u64 > limits.max_nested_mem_read {
            return Ok(Some(threat(
                ZipThreatKind::NestedSizeMismatch,
                format!(
                    "nested archive #{index} inflates beyond its declared size and the {} B read limit",
                    limits.max_nested_mem_read
                ),
            )));
        }
        let inner =
            match inspect_zip_reader(Cursor::new(data.as_slice()), depth + 1, limits, budget) {
                Ok(result) => result,
                Err(_) => raw_overlap_scan(Cursor::new(data.as_slice()), depth + 1),
            };
        if inner.is_some() {
            return Ok(inner);
        }
    }
    Ok(None)
}

pub fn scan_and_respond(path: &Path, cfg: &AppConfig) -> Option<ZipThreat> {
    let threat = inspect_zip_file(path, cfg)?;
    let details = threat.summary();
    let action = if cfg.is_dry_run() {
        "DRY_RUN: would quarantine".to_string()
    } else {
        match quarantine::quarantine_file(path, cfg, "ZIP_BOMB", &details) {
            Ok(meta) => format!("QUARANTINED id={}", meta.id),
            Err(e) => format!("QUARANTINE_FAILED: {e}"),
        }
    };
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "ZIP_BOMB",
            Severity::High,
            path.display().to_string(),
            action,
            details,
        ),
    );
    Some(threat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn build_zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            for (name, data) in files {
                let options =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// Two central-directory records pointing at the same local file (non-recursive bomb shape).
    fn overlapping_zip() -> Vec<u8> {
        let data = vec![b'A'; 4096];
        let crc = crc32(&data);
        let size = data.len() as u32;
        let local_name = b"payload.bin";
        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x21u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(local_name);
        out.extend_from_slice(&data);
        let cd_offset = out.len() as u32;
        for name in [&b"payload.bin"[..], &b"payload-alias.bin"[..]] {
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0x21u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(name);
        }
        let cd_size = out.len() as u32 - cd_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn nested(levels: usize) -> Vec<u8> {
        let mut current = build_zip(&[("leaf.txt", b"hello".to_vec())]);
        for level in 1..levels {
            let name = format!("level{level}.zip");
            current = build_zip(&[(name.as_str(), current)]);
        }
        current
    }

    #[test]
    fn benign_zip_is_allowed() {
        let bytes = build_zip(&[
            ("readme.txt", b"The Nex benign archive".to_vec()),
            (
                "data.bin",
                (0..4096u32).map(|i| (i * 7 % 256) as u8).collect(),
            ),
        ]);
        assert_eq!(inspect_zip_bytes(&bytes, &ZipLimits::default()), None);
    }

    #[test]
    fn small_compressible_zip_is_below_ratio_floor() {
        let bytes = build_zip(&[("zeros.bin", vec![0u8; 256 * 1024])]);
        assert_eq!(inspect_zip_bytes(&bytes, &ZipLimits::default()), None);
    }

    #[test]
    fn ratio_bomb_is_flagged() {
        let limits = ZipLimits {
            min_ratio_check_bytes: 1024 * 1024,
            ..ZipLimits::default()
        };
        let bytes = build_zip(&[("zeros.bin", vec![0u8; 2 * 1024 * 1024])]);
        let threat = inspect_zip_bytes(&bytes, &limits).expect("ratio bomb must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::CompressionRatio);
    }

    #[test]
    fn declared_size_limit_is_enforced() {
        let limits = ZipLimits {
            max_uncompressed_bytes: 1024,
            ..ZipLimits::default()
        };
        let bytes = build_zip(&[("big.bin", vec![7u8; 4096])]);
        let threat = inspect_zip_bytes(&bytes, &limits).expect("size limit must trigger");
        assert_eq!(threat.kind, ZipThreatKind::UncompressedSize);
    }

    #[test]
    fn overlapping_entries_are_flagged() {
        let threat = inspect_zip_bytes(&overlapping_zip(), &ZipLimits::default())
            .expect("overlap must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::OverlappingEntries);
    }

    #[test]
    fn nesting_beyond_limit_is_flagged() {
        assert_eq!(inspect_zip_bytes(&nested(3), &ZipLimits::default()), None);
        let threat = inspect_zip_bytes(&nested(4), &ZipLimits::default())
            .expect("4-level nesting must be flagged");
        assert_eq!(threat.kind, ZipThreatKind::NestingDepth);
        assert_eq!(threat.depth, 4);
    }

    #[test]
    fn non_zip_bytes_are_ignored() {
        assert_eq!(inspect_zip_bytes(b"not a zip", &ZipLimits::default()), None);
    }

    #[test]
    fn partial_downloads_are_ignored() {
        assert!(is_ignored_extension(Path::new("setup.exe.crdownload")));
        assert!(is_ignored_extension(Path::new("a.PART")));
        assert!(!is_ignored_extension(Path::new("a.zip")));
    }
}
