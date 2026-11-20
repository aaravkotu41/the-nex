//! Drives the real `the-nex` binary with sandbox overrides so nothing touches system folders.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use the_nex_core::config::{AppConfig, RuntimeToggles, DATA_DIR_ENV};
use the_nex_core::quarantine::{self, ThreatEvent};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "thenex-cli-{tag}-{}-{}",
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

    fn quarantine(&self) -> PathBuf {
        self.0.join("quarantine")
    }

    fn events(&self) -> PathBuf {
        self.0.join("logs").join("events.jsonl")
    }

    /// Mirrors what the CLI derives from --quarantine-dir / --log-file / THENEX_DATA_DIR.
    fn config(&self) -> AppConfig {
        let cfg = AppConfig::for_base_dir(&self.0.join("data")).with_overrides(
            Some(self.quarantine().as_path()),
            Some(self.events().as_path()),
        );
        cfg.ensure_dirs().unwrap();
        cfg
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_the-nex"))
            .args(args)
            .env(DATA_DIR_ENV, self.0.join("data"))
            .output()
            .unwrap()
    }

    fn run_with_overrides(&self, args: &[&str]) -> Output {
        let quarantine = self.quarantine();
        let events = self.events();
        let mut full: Vec<&str> = args.to_vec();
        full.extend([
            "--quarantine-dir",
            quarantine.to_str().unwrap(),
            "--log-file",
            events.to_str().unwrap(),
        ]);
        self.run(&full)
    }

    fn events_of(&self, threat_type: &str) -> Vec<ThreatEvent> {
        quarantine::read_recent_events(&self.events(), 1 << 20)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.threat_type == threat_type)
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn describe(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Three central-directory entries sharing one local file's data (non-recursive zip bomb).
fn overlapping_zip() -> Vec<u8> {
    let data = vec![b'Z'; 4096];
    let size = data.len() as u32;
    let name = b"kernel.bin";
    let mut out = Vec::new();
    for value in [0x0403_4b50u32] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in [20u16, 0, 0, 0, 0x21] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0u32, size, size] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in [name.len() as u16, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(name);
    out.extend_from_slice(&data);
    let cd_offset = out.len() as u32;
    let aliases: [&[u8]; 3] = [b"kernel.bin", b"alias-1.bin", b"alias-2.bin"];
    for alias in aliases {
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        for value in [20u16, 20, 0, 0, 0, 0x21] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for value in [0u32, size, size] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for value in [alias.len() as u16, 0, 0, 0, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for value in [0u32, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(alias);
    }
    let cd_size = out.len() as u32 - cd_offset;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for value in [0u16, 0, aliases.len() as u16, aliases.len() as u16] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn rejects_bad_arguments_and_ids() {
    let sandbox = Sandbox::new("args");
    assert_eq!(sandbox.run(&["--bogus"]).status.code(), Some(2));
    assert_eq!(
        sandbox.run(&["--install", "--dry-run"]).status.code(),
        Some(2)
    );
    assert_eq!(
        sandbox
            .run(&["--uninstall", "--log-file", "x"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(sandbox.run(&["--restore"]).status.code(), Some(2));
    assert_eq!(sandbox.run(&["--set", "warp=on"]).status.code(), Some(2));
    let help = sandbox.run(&["--help"]);
    assert!(help.status.success());
    let usage = String::from_utf8_lossy(&help.stdout);
    for flag in [
        "--restore <ID>",
        "--quarantine-dir",
        "--log-file",
        "--tray",
        "--quick-scan",
    ] {
        assert!(usage.contains(flag), "usage lacks {flag}");
    }
    let traversal = sandbox.run_with_overrides(&["--restore", "../../etc/passwd"]);
    assert_eq!(traversal.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&traversal.stderr).contains("invalid quarantine ID"));
}

#[test]
fn restore_and_delete_round_trip_through_the_cli() {
    let sandbox = Sandbox::new("restore");
    let cfg = sandbox.config();
    let victim = sandbox.path().join("watch").join("invoice_pack.zip");
    fs::create_dir_all(victim.parent().unwrap()).unwrap();
    fs::write(&victim, b"restored through the CLI").unwrap();
    let meta = quarantine::quarantine_file(&victim, &cfg, "ZIP_BOMB", "cli test").unwrap();
    assert!(!victim.exists());

    let output = sandbox.run_with_overrides(&["--restore", meta.id.as_str()]);
    assert!(output.status.success(), "{}", describe(&output));
    assert_eq!(fs::read(&victim).unwrap(), b"restored through the CLI");
    assert!(!quarantine::meta_path(&cfg, &meta.id).exists());
    assert_eq!(sandbox.events_of("QUARANTINE_RESTORE").len(), 1);

    let again = quarantine::quarantine_file(&victim, &cfg, "ZIP_BOMB", "cli test").unwrap();
    let output = sandbox.run_with_overrides(&["--delete", again.id.as_str()]);
    assert!(output.status.success(), "{}", describe(&output));
    assert!(!again.quarantined_path.exists());
    assert!(!victim.exists());
    assert_eq!(sandbox.events_of("QUARANTINE_DELETE").len(), 1);
}

#[test]
fn set_writes_settings_json() {
    let sandbox = Sandbox::new("set");
    let output = sandbox.run(&["--set", "zip_bomb=off"]);
    assert!(output.status.success(), "{}", describe(&output));
    let output = sandbox.run(&["--set", "dry-run=on"]);
    assert!(output.status.success(), "{}", describe(&output));
    let settings = sandbox.path().join("data").join("settings.json");
    let toggles = RuntimeToggles::load(&settings).unwrap();
    assert!(!toggles.zip_bomb_enabled);
    assert!(toggles.dry_run);
    assert!(toggles.bin_ai_enabled && toggles.process_guard_enabled && toggles.canary_enabled);
}

#[test]
fn quick_scan_finds_bombs_without_touching_them_in_dry_run() {
    let sandbox = Sandbox::new("scan");
    let watch = sandbox.path().join("watch");
    fs::create_dir_all(watch.join("nested")).unwrap();
    let bomb = watch.join("nested").join("overlap_bomb.zip");
    fs::write(&bomb, overlapping_zip()).unwrap();
    fs::write(watch.join("notes.txt"), b"plain text").unwrap();

    let output = sandbox.run_with_overrides(&[
        "--quick-scan",
        "--dry-run",
        "--watch-dir",
        watch.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", describe(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_examined"], 2);
    assert_eq!(report["dry_run"], true);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["threat_type"], "ZIP_BOMB");
    assert!(bomb.exists(), "dry run must not quarantine");

    let zip_events = sandbox.events_of("ZIP_BOMB");
    assert_eq!(zip_events.len(), 1);
    assert!(zip_events[0].action_taken.starts_with("DRY_RUN"));
    assert_eq!(sandbox.events_of("QUICK_SCAN").len(), 1);
    assert!(sandbox
        .events()
        .with_file_name("last_quick_scan.json")
        .is_file());
}
