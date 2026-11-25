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
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
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
    // A privileged run ignores THENEX_DATA_DIR on purpose (config::data_dir), and Windows CI
    // runners are elevated: there `--set` would edit the machine's real settings.json, which
    // the live verifier then inherits (zip bombs off, dry run on). Nothing to sandbox, so
    // nothing to run; RuntimeToggles save/load is covered by the core's unit tests.
    if the_nex_core::config::running_privileged() {
        return;
    }
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
fn scan_file_explains_verdicts_and_changes_nothing() {
    let sandbox = Sandbox::new("scanfile");
    let own = PathBuf::from(env!("CARGO_BIN_EXE_the-nex"));
    let notes = sandbox.path().join("notes.txt");
    fs::write(&notes, b"plain text").unwrap();
    let list = sandbox.path().join("list.txt");
    fs::write(&list, format!("{}\n\n{}\n", own.display(), notes.display())).unwrap();

    let output = sandbox.run(&["--scan-file", &format!("@{}", list.display())]);
    assert!(output.status.success(), "{}", describe(&output));
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{}", describe(&output));

    let exe = &lines[0];
    assert_eq!(exe["verdict"], "clean", "The Nex flags itself: {exe}");
    assert_eq!(exe["features"].as_array().unwrap().len(), 14);
    assert!(
        exe["profile"]["import_count"].as_u64().unwrap() > 0,
        "{exe}"
    );
    assert!(exe["reasons"].is_array());
    let notes_line = &lines[1];
    assert_eq!(notes_line["verdict"], "not_scored", "{notes_line}");
    assert!(notes.exists() && own.exists());
    assert!(
        !sandbox.events().exists(),
        "--scan-file must not log threat events"
    );

    let missing = sandbox.run(&["--scan-file", "definitely-missing.exe"]);
    assert_eq!(missing.status.code(), Some(1));
}

// Unix only: Windows itself drops a trailing space, so both names are one file there.
#[cfg(unix)]
#[test]
fn check_file_checks_the_file_whose_name_was_given_not_a_trimmed_one() {
    let sandbox = Sandbox::new("checkname");
    let dir = sandbox.path().join("files");
    fs::create_dir_all(&dir).unwrap();
    // A harmless (empty) archive under the plain name, a bomb under the name plus a space.
    let (plain, spaced) = (dir.join("pack.zip"), dir.join("pack.zip "));
    let empty_zip = [
        0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    fs::write(&plain, empty_zip).unwrap();
    fs::write(&spaced, overlapping_zip()).unwrap();
    let verdict = |file: &Path| -> String {
        let output = sandbox.run(&["--check-file", file.to_str().unwrap()]);
        assert!(output.status.success(), "{}", describe(&output));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        json["verdict"].as_str().unwrap().to_string()
    };
    assert_eq!(verdict(&plain), "nothing_found");
    assert_eq!(verdict(&spaced), "suspicious");
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn always_allow_commands_work_end_to_end_in_a_temp_data_folder() {
    // A privileged run ignores THENEX_DATA_DIR (see `set_writes_settings_json`).
    if the_nex_core::config::running_privileged() {
        return;
    }
    use the_nex_core::quarantine::Severity;
    let sandbox = Sandbox::new("allow");
    let cfg = sandbox.config();
    let listed = || -> Vec<serde_json::Value> {
        let out = sandbox.run_with_overrides(&["--list-allowed"]);
        assert!(out.status.success(), "{}", describe(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    };
    assert!(listed().is_empty());

    // --allow and --disallow, by hash, for admins.
    let sha = "ab".repeat(32);
    let add = [
        "--allow",
        sha.as_str(),
        "--allow-name",
        "tool.exe",
        "--allow-type",
        "ZIP_BOMB",
    ];
    let out = sandbox.run_with_overrides(&add);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Added"));
    assert!(
        String::from_utf8_lossy(&sandbox.run_with_overrides(&add).stdout)
            .contains("Already listed")
    );
    let entries = listed();
    assert_eq!(
        (entries.len(), entries[0]["name"].as_str()),
        (1, Some("tool.exe"))
    );
    for bad in [
        vec!["--allow", "abc"],
        vec!["--allow", sha.as_str(), "--allow-type", "LOTL_SCRIPT"],
        vec!["--allow", sha.as_str(), "--allow-type", "KNOWN_MALWARE"],
        vec!["--disallow", "zz"],
    ] {
        assert_eq!(
            sandbox.run_with_overrides(&bad).status.code(),
            Some(2),
            "{bad:?}"
        );
    }
    let out = sandbox.run_with_overrides(&["--disallow", sha.as_str()]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Removed"),
        "{}",
        describe(&out)
    );
    let out = sandbox.run_with_overrides(&["--disallow", sha.as_str()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Not listed"));
    assert!(listed().is_empty());

    // --allow-event: the hash is the one in this folder's own log.
    let victim = sandbox.path().join("watch").join("pack.zip");
    fs::create_dir_all(victim.parent().unwrap()).unwrap();
    fs::write(&victim, b"quarantined and logged").unwrap();
    let meta = quarantine::quarantine_file(&victim, &cfg, "ZIP_BOMB", "cli test").unwrap();
    let event = |kind: &str, action: &str, sha256: Option<&str>| {
        let mut e = ThreatEvent::new(
            kind,
            Severity::High,
            victim.display().to_string(),
            action,
            "d",
        );
        e.sha256 = sha256.map(str::to_string);
        quarantine::append_event(&cfg, &e).unwrap();
        e
    };
    let zip = event(
        "ZIP_BOMB",
        &format!("QUARANTINED id={}", meta.id),
        Some(&meta.sha256),
    );
    let lotl = event("LOTL_SCRIPT", "KILLED", None);
    let forged_lotl = event("LOTL_SCRIPT", "KILLED", Some(&sha));
    let forged_known = event("KNOWN_MALWARE", "KILLED", Some(&sha));
    let unhashed = event("MALWARE_AI", "ALERT_ONLY", None);

    // --expect binds it to the hash a prompt showed: another one changes nothing.
    let shown = meta.sha256.as_str();
    // The 16 digits a prompt shows are right here, and the rest is another file's.
    let same_start = format!("{}{}", &shown[..16], "0".repeat(48));
    for (mode, id) in [
        ("--allow-event", zip.id.as_str()),
        ("--allow-quarantined", meta.id.as_str()),
    ] {
        for other in [&"0123456789abcdef".repeat(4), &same_start] {
            let out = sandbox.run_with_overrides(&[mode, id, "--expect", other]);
            assert_eq!(out.status.code(), Some(1), "{mode}: {}", describe(&out));
            assert!(
                stderr(&out).contains("nothing was allowed"),
                "{}",
                describe(&out)
            );
        }
        for bad in ["", "abc", &"z".repeat(64), &shown[..16]] {
            let out = sandbox.run_with_overrides(&[mode, id, "--expect", bad]);
            assert_eq!(out.status.code(), Some(2), "{mode} {bad}");
        }
    }
    assert!(listed().is_empty() && quarantine::load_meta(&meta.id, &cfg).is_ok());

    let out = sandbox.run_with_overrides(&["--allow-event", zip.id.as_str(), "--expect", shown]);
    assert!(out.status.success(), "{}", describe(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Added") && text.contains("still in quarantine"),
        "{text}"
    );
    let entries = listed();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["sha256"], meta.sha256.as_str());
    assert_eq!(entries[0]["name"], "pack.zip");
    assert_eq!(entries[0]["threat_type"], "ZIP_BOMB");
    let again = sandbox.run_with_overrides(&["--allow-event", zip.id.as_str()]);
    assert!(String::from_utf8_lossy(&again.stdout).contains("Already listed"));

    for (id, why) in [
        (lotl.id.as_str(), "no recorded file hash"),
        (unhashed.id.as_str(), "no recorded file hash"),
        (forged_lotl.id.as_str(), "cannot be always allowed"),
        (forged_known.id.as_str(), "cannot be always allowed"),
        ("20200101000000000-1-0000", "no longer in the log"),
    ] {
        let out = sandbox.run_with_overrides(&["--allow-event", id]);
        assert_eq!(out.status.code(), Some(1), "{id}: {}", describe(&out));
        assert!(stderr(&out).contains(why), "{id}: {}", describe(&out));
    }
    for bad in ["../x", "a b", "x/y"] {
        assert_eq!(
            sandbox
                .run_with_overrides(&["--allow-event", bad])
                .status
                .code(),
            Some(2),
            "{bad}"
        );
    }
    assert_eq!(
        sandbox.run_with_overrides(&["--allow-event"]).status.code(),
        Some(2)
    );
    assert_eq!(listed().len(), 1, "nothing else was allowed");
    assert!(
        quarantine::load_meta(&meta.id, &cfg).is_ok(),
        "allowing never restores"
    );

    // --allow-quarantined restores and allows; known malware and bad IDs are refused.
    let out = sandbox.run_with_overrides(&["--disallow", &meta.sha256]);
    assert!(out.status.success(), "{}", describe(&out));
    let out = sandbox.run_with_overrides(&[
        "--allow-quarantined",
        meta.id.as_str(),
        "--expect",
        &shown.to_uppercase(),
    ]);
    assert!(out.status.success(), "{}", describe(&out));
    assert_eq!(fs::read(&victim).unwrap(), b"quarantined and logged");
    assert_eq!(listed()[0]["sha256"], meta.sha256.as_str());

    let bad = sandbox.path().join("watch").join("bad.exe");
    fs::write(&bad, b"on the list").unwrap();
    let known = quarantine::quarantine_file(&bad, &cfg, "KNOWN_MALWARE", "cli test").unwrap();
    let out = sandbox.run_with_overrides(&["--allow-quarantined", known.id.as_str()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(!bad.exists() && quarantine::load_meta(&known.id, &cfg).is_ok());
    assert_eq!(listed().len(), 1);
    let out = sandbox.run_with_overrides(&["--allow-quarantined", "../../etc/passwd"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("invalid quarantine ID"),
        "{}",
        describe(&out)
    );
}
