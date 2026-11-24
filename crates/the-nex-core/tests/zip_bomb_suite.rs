//! Zip-bomb detector suite. All archives are tiny, built in memory, and never touch the network.

use std::io::{Cursor, Write};

use the_nex_core::config::ZipLimits;
use the_nex_core::zip_bomb::{inspect_zip_bytes, ZipThreatKind};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

fn build_zip(files: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        for (name, data) in files {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(method),
                )
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

fn deflated(files: &[(&str, &[u8])]) -> Vec<u8> {
    build_zip(files, CompressionMethod::Deflated)
}

fn kind(bytes: &[u8], limits: &ZipLimits) -> Option<ZipThreatKind> {
    inspect_zip_bytes(bytes, limits).map(|t| t.kind)
}

fn find(bytes: &[u8], sig: [u8; 4], nth: usize) -> usize {
    bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == sig)
        .nth(nth)
        .map(|(i, _)| i)
        .expect("signature present")
}

const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDFH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

fn put32(bytes: &mut [u8], at: usize, v: u32) {
    bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

/// Overwrites the declared uncompressed size in the first entry's local and central headers.
fn lie_about_size(bytes: &mut [u8], declared: u32) {
    let l = find(bytes, LFH, 0);
    let c = find(bytes, CDFH, 0);
    put32(bytes, l + 22, declared);
    put32(bytes, c + 24, declared);
}

/// Hand-built entry parts: (local header + data, central record).
fn raw_entry(
    name: &[u8],
    method: u16,
    comp: u32,
    unc: u32,
    data: &[u8],
    lho: u32,
) -> (Vec<u8>, Vec<u8>) {
    let mut local = Vec::new();
    local.extend_from_slice(&[0x50, 0x4b, 3, 4]);
    local.extend_from_slice(&20u16.to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(&method.to_le_bytes());
    local.extend_from_slice(&[0, 0, 0x21, 0]);
    local.extend_from_slice(&0u32.to_le_bytes());
    local.extend_from_slice(&comp.to_le_bytes());
    local.extend_from_slice(&unc.to_le_bytes());
    local.extend_from_slice(&(name.len() as u16).to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(name);
    local.extend_from_slice(data);
    let mut cd = Vec::new();
    cd.extend_from_slice(&[0x50, 0x4b, 1, 2]);
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&20u16.to_le_bytes());
    cd.extend_from_slice(&0u16.to_le_bytes());
    cd.extend_from_slice(&method.to_le_bytes());
    cd.extend_from_slice(&[0, 0, 0x21, 0]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&comp.to_le_bytes());
    cd.extend_from_slice(&unc.to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0; 8]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(&lho.to_le_bytes());
    cd.extend_from_slice(name);
    (local, cd)
}

fn eocd(entries: u16, cd_size: u32, cd_offset: u32) -> Vec<u8> {
    let mut out = vec![0x50, 0x4b, 5, 6, 0, 0, 0, 0];
    out.extend_from_slice(&entries.to_le_bytes());
    out.extend_from_slice(&entries.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Assembles locals, then the central directory, then an EOCD.
fn assemble(parts: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = parts.iter().flat_map(|p| p.0.clone()).collect();
    let cd_offset = out.len() as u32;
    let cd: Vec<u8> = parts.iter().flat_map(|p| p.1.clone()).collect();
    out.extend_from_slice(&cd);
    out.extend_from_slice(&eocd(parts.len() as u16, cd.len() as u32, cd_offset));
    out
}

/// A single stored entry carrying Zip64 sizes in its central-directory extra field.
fn zip64_entry(unc: u64, comp: u64, data: &[u8]) -> Vec<u8> {
    let name = b"big.bin";
    let (mut local, _) = raw_entry(name, 0, 0xFFFF_FFFF, 0xFFFF_FFFF, data, 0);
    local.truncate(local.len() - data.len());
    local.extend_from_slice(data);
    let cd_start = local.len();
    let mut cd = raw_entry(name, 0, 0xFFFF_FFFF, 0xFFFF_FFFF, &[], 0).1;
    put16(&mut cd, 30, 20);
    cd.extend_from_slice(&1u16.to_le_bytes());
    cd.extend_from_slice(&16u16.to_le_bytes());
    cd.extend_from_slice(&unc.to_le_bytes());
    cd.extend_from_slice(&comp.to_le_bytes());
    let mut out = local;
    let cd_len = cd.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&eocd(1, cd_len, cd_start as u32));
    out
}

fn small_limits() -> ZipLimits {
    ZipLimits {
        min_ratio_check_bytes: 1024 * 1024,
        ..ZipLimits::default()
    }
}

#[test]
fn normal_archives_are_not_flagged() {
    let text = b"hello hello hello hello\n".repeat(200);
    let noise: Vec<u8> = (0..20_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    for method in [CompressionMethod::Stored, CompressionMethod::Deflated] {
        let bytes = build_zip(
            &[("a.txt", &text), ("dir/b.bin", &noise), ("empty", b"")],
            method,
        );
        assert_eq!(kind(&bytes, &ZipLimits::default()), None, "{method:?}");
    }
}

#[test]
fn prepended_stub_is_handled() {
    let good = deflated(&[("a.txt", b"hi there")]);
    let mut with_stub = vec![b'M', b'Z', 0x90, 0];
    with_stub.extend(std::iter::repeat_n(0xCCu8, 3000));
    with_stub.extend_from_slice(&good);
    assert_eq!(kind(&with_stub, &ZipLimits::default()), None);

    // The same stub must not hide overlapping entries (offsets are stub-relative).
    let (l, c0) = raw_entry(b"a", 0, 8, 8, b"AAAAAAAA", 0);
    let c1 = raw_entry(b"b", 0, 8, 8, b"", 0).1;
    let mut bomb = vec![0x90u8; 777];
    bomb.extend(assemble(&[(l, c0), (Vec::new(), c1)]));
    assert_eq!(
        kind(&bomb, &ZipLimits::default()),
        Some(ZipThreatKind::OverlappingEntries)
    );
}

#[test]
fn quoted_header_at_end_of_neighbour_is_flagged() {
    // B's local header sits in the last bytes of A's data; B's data begins exactly where A's
    // data ends, so the data ranges merely touch and only whole-entry extents overlap.
    let (b_local, b_cd) = raw_entry(b"b", 0, 4, 4, b"BBBB", 0);
    let header_len = b_local.len() - 4;
    let a_name = b"a";
    let a_data_start = 30 + a_name.len();
    let filler = 10usize;
    let mut a_data = vec![b'x'; filler];
    a_data.extend_from_slice(&b_local[..header_len]);
    let a_len = a_data.len() as u32;
    let (mut a_local, a_cd) = raw_entry(a_name, 0, a_len, a_len, &a_data, 0);
    a_local.extend_from_slice(b"BBBB");
    let mut b_cd = b_cd;
    put32(&mut b_cd, 42, (a_data_start + filler) as u32);
    let bytes = assemble(&[(a_local, a_cd), (Vec::new(), b_cd)]);
    assert_eq!(
        kind(&bytes, &ZipLimits::default()),
        Some(ZipThreatKind::OverlappingEntries)
    );
}

#[test]
fn single_entry_bomb_hidden_among_incompressible_data_is_flagged() {
    let zeros = vec![0u8; 4 * 1024 * 1024];
    let mut seed = 0x1234_5678u32;
    let noise: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut w = ZipWriter::new(&mut cursor);
        let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let defl = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        w.start_file("noise.bin", stored).unwrap();
        w.write_all(&noise).unwrap();
        w.start_file("zeros.bin", defl).unwrap();
        w.write_all(&zeros).unwrap();
        w.finish().unwrap();
    }
    let bytes = cursor.into_inner();
    let t = inspect_zip_bytes(&bytes, &small_limits()).expect("per-entry ratio");
    assert_eq!(t.kind, ZipThreatKind::CompressionRatio);
    assert!(t.detail.contains("entry"), "{}", t.detail);
}

#[test]
fn zip64_sizes_above_4gib_are_read() {
    let big = 8u64 * 1024 * 1024 * 1024;
    let bytes = zip64_entry(big, 4096, &[7u8; 4096]);
    assert_eq!(
        kind(&bytes, &ZipLimits::default()),
        Some(ZipThreatKind::UncompressedSize)
    );
    let lenient = ZipLimits {
        max_uncompressed_bytes: u64::MAX,
        ..ZipLimits::default()
    };
    assert_eq!(
        kind(&bytes, &lenient),
        Some(ZipThreatKind::CompressionRatio)
    );
    // A Zip64 record that is honest stays quiet.
    assert_eq!(kind(&zip64_entry(4096, 4096, &[7u8; 4096]), &lenient), None);
}

/// An EOCD plus Zip64 record declaring `count` entries and no central directory at all.
fn zip64_count_declaration(count: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let z64_at = out.len() as u64;
    out.extend_from_slice(&[0x50, 0x4b, 6, 6]);
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&[45, 0, 45, 0]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&[0x50, 0x4b, 6, 7, 0, 0, 0, 0]);
    out.extend_from_slice(&z64_at.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&[0x50, 0x4b, 5, 6, 0, 0, 0, 0]);
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn absurd_zip64_entry_count_is_flagged() {
    for count in [1u64 << 40, 50_000_000] {
        assert_eq!(
            kind(&zip64_count_declaration(count), &ZipLimits::default()),
            Some(ZipThreatKind::EntryCount),
            "{count}"
        );
    }
}

#[test]
fn imagenet_scale_entry_count_is_not_flagged_for_count_alone() {
    // 1.3M declared entries with no directory behind them: unparsable, but never EntryCount.
    let k = kind(&zip64_count_declaration(1_300_000), &ZipLimits::default());
    assert_ne!(k, Some(ZipThreatKind::EntryCount));
}

#[test]
fn archive_with_more_than_65535_entries_is_fine() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut w = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for i in 0..66_000u32 {
            w.start_file(format!("f{i}"), opts).unwrap();
        }
        w.finish().unwrap();
    }
    assert_eq!(kind(&cursor.into_inner(), &ZipLimits::default()), None);
}

#[test]
fn stored_entry_with_lying_size_is_flagged() {
    let (l, c) = raw_entry(b"liar.bin", 0, 10, 1000, &[1u8; 10], 0);
    let bytes = assemble(&[(l, c)]);
    let t = inspect_zip_bytes(&bytes, &ZipLimits::default()).expect("stored lie");
    assert_eq!(t.kind, ZipThreatKind::NestedSizeMismatch);
}

#[test]
fn local_header_disagreeing_with_central_directory_is_flagged() {
    let base = deflated(&[("a.txt", &b"abcdefgh".repeat(100))]);
    assert_eq!(kind(&base, &ZipLimits::default()), None);

    let mut method = base.clone();
    let l = find(&method, LFH, 0);
    put16(&mut method, l + 8, 0);
    assert_eq!(
        kind(&method, &ZipLimits::default()),
        Some(ZipThreatKind::HeaderMismatch)
    );

    let mut sizes = base.clone();
    put32(&mut sizes, l + 22, 12345);
    assert_eq!(
        kind(&sizes, &ZipLimits::default()),
        Some(ZipThreatKind::HeaderMismatch)
    );
}

#[test]
fn deflate_entry_inflating_past_declared_size_is_flagged() {
    let mut bytes = deflated(&[("zeros.bin", &vec![0u8; 2 * 1024 * 1024])]);
    assert_eq!(kind(&bytes, &ZipLimits::default()), None);
    lie_about_size(&mut bytes, 100);
    let t = inspect_zip_bytes(&bytes, &ZipLimits::default()).expect("lying declared size");
    assert_eq!(t.kind, ZipThreatKind::NestedSizeMismatch);
}

#[test]
fn nested_archive_with_lying_size_is_flagged() {
    let inner = deflated(&[("z", &vec![0u8; 2 * 1024 * 1024])]);
    let mut outer = deflated(&[("inner.zip", &inner)]);
    lie_about_size(&mut outer, 64);
    assert_eq!(
        kind(&outer, &ZipLimits::default()),
        Some(ZipThreatKind::NestedSizeMismatch)
    );
}

#[test]
fn nested_ratios_multiply() {
    // Inner: ~1000:1 (under the raised limit). Outer deflates the inner zip's repetitive
    // stream again, so the file on disk is far smaller than the sum of its parts.
    let inner = deflated(&[("z", &vec![0u8; 8 * 1024 * 1024])]);
    let outer = deflated(&[("inner.zip", &inner)]);
    let limits = ZipLimits {
        max_ratio: 1500.0,
        min_ratio_check_bytes: 4 * 1024 * 1024,
        ..ZipLimits::default()
    };
    let t = inspect_zip_bytes(&outer, &limits).expect("effective nested ratio");
    assert_eq!(t.kind, ZipThreatKind::CompressionRatio);
    assert!(t.detail.contains("nested"), "{}", t.detail);
}

#[test]
fn hostile_filenames_are_not_bombs() {
    let bytes = deflated(&[
        ("../../etc/passwd", b"x"),
        ("/abs/path.txt", b"x"),
        ("C:\\win\\evil.dll", b"x"),
        ("nul\0byte.txt", b"x"),
    ]);
    assert_eq!(kind(&bytes, &ZipLimits::default()), None);
}

#[test]
fn truncated_archives_never_panic_or_false_positive() {
    let good = deflated(&[("a.txt", &b"abc".repeat(500)), ("b.bin", &[9u8; 300])]);
    for cut in 0..good.len() {
        let t = inspect_zip_bytes(&good[..cut], &ZipLimits::default());
        assert_eq!(t, None, "prefix of {cut} bytes");
    }
}

#[test]
fn random_and_mutated_bytes_never_panic() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seeds = [
        deflated(&[
            ("a.txt", &b"abc".repeat(300)),
            ("n.zip", &deflated(&[("x", b"y")])),
        ]),
        zip64_entry(1 << 33, 16, &[1u8; 16]),
        assemble(&[raw_entry(b"s", 0, 4, 4, b"ABCD", 0)]),
    ];
    for seed in &seeds {
        for _ in 0..400 {
            let mut bytes = seed.clone();
            for _ in 0..(1 + next() % 6) {
                let at = (next() % bytes.len() as u64) as usize;
                bytes[at] = next() as u8;
            }
            if next() % 3 == 0 {
                bytes.truncate((next() % bytes.len() as u64) as usize);
            }
            let _ = inspect_zip_bytes(&bytes, &small_limits());
        }
    }
    for _ in 0..300 {
        let len = (next() % 600) as usize;
        let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if len > 30 && next() % 2 == 0 {
            let at = len - 22;
            bytes[at..at + 4].copy_from_slice(&[0x50, 0x4b, 5, 6]);
        }
        let _ = inspect_zip_bytes(&bytes, &small_limits());
    }
}

/// Inserts `junk` between the central directory and the EOCD (the last 22 bytes).
fn with_junk_before_eocd(bytes: &[u8], junk: &[u8]) -> Vec<u8> {
    let at = bytes.len() - 22;
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(junk);
    out.extend_from_slice(&bytes[at..]);
    out
}

#[test]
fn junk_between_directory_and_eocd_cannot_hide_a_bomb() {
    // ~200 KB archive holding 200 MiB of zeros, with default limits.
    let bomb = deflated(&[("zeros.bin", &vec![0u8; 200 * 1024 * 1024])]);
    assert_eq!(
        kind(&bomb, &ZipLimits::default()),
        Some(ZipThreatKind::CompressionRatio)
    );
    for junk in [&[1u8, 2, 3, 4][..], &[0xAB; 5000][..]] {
        let hidden = with_junk_before_eocd(&bomb, junk);
        assert_eq!(
            kind(&hidden, &ZipLimits::default()),
            Some(ZipThreatKind::CompressionRatio),
            "{} junk bytes",
            junk.len()
        );
    }
}

#[test]
fn junk_and_stub_together_cannot_hide_a_bomb() {
    let bomb = deflated(&[("zeros.bin", &vec![0u8; 2 * 1024 * 1024])]);
    let mut hidden = vec![0x90u8; 513];
    hidden.extend(with_junk_before_eocd(&bomb, &[7u8; 33]));
    assert_eq!(
        kind(&hidden, &small_limits()),
        Some(ZipThreatKind::CompressionRatio)
    );
}

#[test]
fn destroyed_directory_is_judged_by_local_headers() {
    let mut bomb = deflated(&[("zeros.bin", &vec![0u8; 2 * 1024 * 1024])]);
    let c = find(&bomb, CDFH, 0);
    bomb[c..c + 4].copy_from_slice(b"JUNK");
    assert_eq!(
        kind(&bomb, &small_limits()),
        Some(ZipThreatKind::CompressionRatio)
    );
}

#[test]
fn unparsable_archive_with_eocd_is_flagged_malformed() {
    let mut bytes = b"garbage!".repeat(8);
    bytes.extend(eocd(3, 40, 0));
    assert_eq!(
        kind(&bytes, &ZipLimits::default()),
        Some(ZipThreatKind::Malformed)
    );
}

#[test]
fn nested_archive_lying_above_read_cap_is_still_inspected() {
    let inner = deflated(&[("z", &vec![0u8; 2 * 1024 * 1024])]);
    let mut outer = deflated(&[("inner.zip", &inner)]);
    // Declares 4 MiB (over the 1 MiB read cap) while really being a ~2 KB archive.
    lie_about_size(&mut outer, 4 * 1024 * 1024);
    let limits = ZipLimits {
        max_ratio: 1e12,
        max_nested_mem_read: 1024 * 1024,
        ..ZipLimits::default()
    };
    let t = inspect_zip_bytes(&outer, &limits).expect("lying declaration must not hide it");
    assert_eq!(t.kind, ZipThreatKind::NestedSizeMismatch);
    assert!(t.detail.contains("yields only"), "{}", t.detail);
}

#[test]
fn honest_nested_archive_over_read_cap_with_bomb_ratio_is_flagged() {
    // Under the ratio floor at the top level, over the memory cap, and 1000:1 in practice.
    let outer = deflated(&[("big.zip", &vec![0u8; 4 * 1024 * 1024])]);
    let limits = ZipLimits {
        max_ratio: 100.0,
        max_nested_mem_read: 1024 * 1024,
        min_ratio_check_bytes: 64 * 1024 * 1024,
        ..ZipLimits::default()
    };
    let t = inspect_zip_bytes(&outer, &limits).expect("cannot be verified");
    assert_eq!(t.kind, ZipThreatKind::NestedSizeMismatch);
    assert!(t.detail.contains("cannot be verified"), "{}", t.detail);
}

#[cfg(unix)]
mod files {
    use super::*;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;
    use the_nex_core::config::AppConfig;
    use the_nex_core::zip_bomb::{inspect_zip_file, wait_for_file_ready};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zbsuite-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fifo_never_hangs_the_scanner() {
        let dir = scratch("fifo");
        let fifo = dir.join("pipe.zip");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let (tx, rx) = mpsc::channel();
        let (p, base) = (fifo.clone(), dir.clone());
        std::thread::spawn(move || {
            let cfg = AppConfig::for_base_dir(&base);
            let _ = tx.send((inspect_zip_file(&p, &cfg), wait_for_file_ready(&p)));
        });
        let (threat, ready) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("scanner hung on a FIFO");
        assert_eq!(threat, None);
        assert!(!ready);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinks_are_never_followed() {
        let dir = scratch("symlink");
        let real = dir.join("real.zip");
        std::fs::write(&real, deflated(&[("z", &vec![0u8; 2 * 1024 * 1024])])).unwrap();
        let cfg = AppConfig::for_base_dir(&dir);
        let mut cfg = cfg;
        cfg.zip_limits = small_limits();
        assert!(
            inspect_zip_file(&real, &cfg).is_some(),
            "control: real file is a bomb"
        );
        let link = dir.join("link.zip");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(inspect_zip_file(&link, &cfg), None);
        assert!(!wait_for_file_ready(&link));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
