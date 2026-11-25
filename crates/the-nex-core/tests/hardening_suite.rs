//! Regression tests for the root/SYSTEM-daemon hardening audit (symlink and path-trust fixes).
//! Unix-only where they need symlinks; they only touch temp directories.

use std::fs;
use std::path::PathBuf;
use the_nex_core::{logger, platform};

fn temp_root(tag: &str) -> PathBuf {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("thenex-hard-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn logger_escapes_line_breaks() {
    let root = temp_root("log");
    logger::init(&root, false);
    logger::info("victim\n2099-01-01T00:00:00Z [ERROR] forged\r[WARN] x");
    let text = fs::read_to_string(root.join("thenex.log")).unwrap();
    assert!(text.contains("victim\\n2099-01-01T00:00:00Z [ERROR] forged\\r[WARN] x"));
    assert!(!text.lines().any(|l| l.starts_with("2099")));
    logger::init_without_file(false);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn path_is_within_rejects_parent_dir() {
    let root = temp_root("within");
    assert!(platform::path_is_within(&root.join("a/b"), &root));
    assert!(!platform::path_is_within(&root.join("a/../../etc"), &root));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::sync::Arc;
    use the_nex_core::canary::{self, CanaryManager, CanaryState, CANARY_FILE_NAMES};
    use the_nex_core::config::AppConfig;
    use the_nex_core::quarantine;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn victim(root: &Path) -> PathBuf {
        let target = root.join("sudoers");
        fs::write(&target, b"root ALL").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();
        target
    }

    fn assert_untouched(target: &Path) {
        assert_eq!(mode(target), 0o444);
        assert_eq!(fs::read(target).unwrap(), b"root ALL");
    }

    #[test]
    fn canary_paths_never_follow_symlinks() {
        let root = temp_root("canary");
        let dir = root.join("Desktop");
        fs::create_dir_all(&dir).unwrap();
        let target = victim(&root);
        let link = dir.join(CANARY_FILE_NAMES[0]);

        // read: treated as tampered, not followed
        symlink(&target, &link).unwrap();
        assert_eq!(canary::check_canary(&link, 0), CanaryState::Modified);

        // rearm replaces the link with a real 0644 canary (the GUI verifies as the user)
        let report = canary::rearm_canaries(std::slice::from_ref(&dir));
        assert!(report.iter().all(|c| c.state == "Intact"), "{report:?}");
        assert_untouched(&target);
        assert!(!fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(mode(&link), 0o644);

        // write_canary
        fs::remove_file(&link).unwrap();
        symlink(&target, &link).unwrap();
        let cfg = Arc::new(AppConfig::for_base_dir(&root.join("base")));
        let manager = CanaryManager::new(cfg, vec![dir.clone()]);
        manager.write_canary(&link, 0).unwrap();
        assert_untouched(&target);
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());

        // remove unlinks the link only
        fs::remove_file(&link).unwrap();
        symlink(&target, &link).unwrap();
        canary::remove_canaries(&AppConfig::for_base_dir(&dir), std::slice::from_ref(&dir));
        assert!(fs::symlink_metadata(&link).is_err());
        assert_untouched(&target);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_canary_does_not_create_through_a_dangling_link() {
        let root = temp_root("excl");
        let target = root.join("not-yet");
        let link = root.join("c");
        symlink(&target, &link).unwrap();
        canary::replace_canary(&link, b"x").unwrap();
        assert!(!target.exists());
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn set_readonly_refuses_symlinks_and_clears_safely() {
        let root = temp_root("ro");
        let target = victim(&root);
        let link = root.join("link");
        symlink(&target, &link).unwrap();
        let err = quarantine::set_readonly(&link, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_untouched(&target);

        // clearing read-only on a regular file grants owner write only (not 0666)
        quarantine::set_readonly(&target, false).unwrap();
        assert_eq!(mode(&target), 0o644);
        quarantine::set_readonly(&target, true).unwrap();
        assert_eq!(mode(&target), 0o444);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_refuses_symlinks() {
        let root = temp_root("qsym");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let target = victim(&root);
        let link = root.join("evil.exe");
        symlink(&target, &link).unwrap();
        let err = quarantine::quarantine_file(&link, &cfg, "T", "d").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(fs::symlink_metadata(&link).is_ok());
        assert_untouched(&target);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_refuses_a_folder_swapped_for_a_symlink() {
        let root = temp_root("qdir");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        // ~/Downloads/x was a folder when scanned; now it is a link into a system-like folder.
        let sensitive = root.join("etc");
        fs::create_dir_all(&sensitive).unwrap();
        let sudoers = sensitive.join("sudoers");
        fs::write(&sudoers, b"root ALL=(ALL) ALL").unwrap();
        let swapped = root.join("x");
        symlink(&sensitive, &swapped).unwrap();
        let err =
            quarantine::quarantine_file(&swapped.join("sudoers"), &cfg, "T", "d").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&sudoers).unwrap(), b"root ALL=(ALL) ALL");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lock_and_unlock_refuse_symlinks() {
        let root = temp_root("lock");
        let target = victim(&root);
        let link = root.join("link");
        symlink(&target, &link).unwrap();
        platform::lock_quarantined_file(&link);
        platform::unlock_restored_file(&link);
        assert_untouched(&target);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_meta_rejects_foreign_or_traversing_paths() {
        let root = temp_root("meta");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let file = root.join("v.bin");
        fs::write(&file, b"MZ").unwrap();
        let good = quarantine::quarantine_file(&file, &cfg, "T", "d").unwrap();
        assert!(quarantine::load_meta(&good.id, &cfg).is_ok());

        let write = |quarantined: &Path, original: &Path| {
            let mut meta = good.clone();
            meta.quarantined_path = quarantined.to_path_buf();
            meta.original_path = original.to_path_buf();
            fs::write(
                quarantine::meta_path(&cfg, &good.id),
                serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
        };
        // outside the quarantine folder
        write(&root.join("elsewhere"), &file);
        assert!(quarantine::load_meta(&good.id, &cfg).is_err());
        // a subfolder is not a direct child
        write(&cfg.quarantine_dir.join("sub/x"), &file);
        assert!(quarantine::load_meta(&good.id, &cfg).is_err());
        // `..` inside either stored path
        write(&cfg.quarantine_dir.join("../x"), &file);
        assert!(quarantine::load_meta(&good.id, &cfg).is_err());
        write(&good.quarantined_path, &root.join("a/../../etc/passwd"));
        assert!(quarantine::load_meta(&good.id, &cfg).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_refuses_swapped_parent_and_existing_links() {
        let root = temp_root("restore");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let folder = root.join("docs");
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join("report.exe");
        fs::write(&file, b"MZ payload").unwrap();
        let meta = quarantine::quarantine_file(&file, &cfg, "T", "d").unwrap();
        assert!(meta.owner_uid.is_some());

        // parent folder swapped for a link elsewhere
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let moved = root.join("docs-moved");
        fs::rename(&folder, &moved).unwrap();
        symlink(&elsewhere, &folder).unwrap();
        assert!(quarantine::restore_file(&meta.id, &cfg).is_err());
        assert!(!elsewhere.join("report.exe").exists());
        assert!(meta.quarantined_path.exists());

        // restored name already taken by a dangling symlink: not overwritten
        fs::remove_file(&folder).unwrap();
        fs::rename(&moved, &folder).unwrap(); // the original folder (same inode) is back
        symlink(root.join("nowhere"), &file).unwrap();
        let err = quarantine::restore_file(&meta.id, &cfg).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!root.join("nowhere").exists());

        // clean destination restores
        fs::remove_file(&file).unwrap();
        quarantine::restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"MZ payload");
        let _ = fs::remove_dir_all(&root);
    }

    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn fifo_in_place_of_a_canary_does_not_hang() {
        let root = temp_root("fifo");
        let fifo = root.join(CANARY_FILE_NAMES[0]);
        mkfifo(&fifo);
        let started = std::time::Instant::now();
        assert_eq!(canary::check_canary(&fifo, 0), CanaryState::Modified);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // quarantine / chmod helpers refuse it too, also without blocking
        assert!(quarantine::open_nofollow(&fifo).is_err());
        assert!(quarantine::set_readonly(&fifo, true).is_err());
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        assert!(quarantine::quarantine_file(&fifo, &cfg, "T", "d").is_err());
        // rearm replaces it with a real canary
        let report = canary::rearm_canaries(std::slice::from_ref(&root));
        assert!(report.iter().all(|c| c.state == "Intact"), "{report:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_canary_is_modified_not_slurped() {
        let root = temp_root("big");
        let path = root.join(CANARY_FILE_NAMES[0]);
        fs::write(&path, vec![0u8; 5 * 1024 * 1024]).unwrap();
        assert_eq!(canary::check_canary(&path, 0), CanaryState::Modified);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn symlinked_canary_folder_is_skipped() {
        let root = temp_root("dirlink");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        let link = root.join("Desktop");
        symlink(&real, &link).unwrap();
        let cfg = Arc::new(AppConfig::for_base_dir(&root.join("base")));
        let mut manager = CanaryManager::new(cfg, vec![link.clone()]);
        assert_eq!(manager.deploy_all(), 0);
        assert!(canary::rearm_canaries(std::slice::from_ref(&link)).is_empty());
        assert!(canary::canary_states(std::slice::from_ref(&link)).is_empty());
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_refuses_hardlinks_and_keeps_owner_and_mode() {
        let root = temp_root("qhard");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let file = root.join("tool.bin");
        fs::write(&file, b"MZ").unwrap();
        fs::hard_link(&file, root.join("alias.bin")).unwrap();
        let err = quarantine::quarantine_file(&file, &cfg, "T", "d").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(file.exists());
        fs::remove_file(root.join("alias.bin")).unwrap();

        fs::set_permissions(&file, fs::Permissions::from_mode(0o750)).unwrap();
        let meta = quarantine::quarantine_file(&file, &cfg, "T", "d").unwrap();
        assert_eq!(meta.original_mode, Some(0o750));
        assert!(meta.parent_dev.is_some() && meta.parent_ino.is_some());
        quarantine::restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(mode(&file), 0o750); // original mode, not a blanket 0644
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_refuses_a_different_folder_at_the_same_path() {
        let root = temp_root("qino");
        let cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.ensure_dirs().unwrap();
        let folder = root.join("docs");
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join("a.exe");
        fs::write(&file, b"MZ").unwrap();
        let meta = quarantine::quarantine_file(&file, &cfg, "T", "d").unwrap();
        // same path, different directory (new inode)
        fs::remove_dir_all(&folder).unwrap();
        fs::create_dir_all(&folder).unwrap();
        let err = quarantine::restore_file(&meta.id, &cfg).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!file.exists() && meta.quarantined_path.exists());
        // an old record without the identity fields still restores
        let mut old = quarantine::load_meta(&meta.id, &cfg).unwrap();
        old.parent_dev = None;
        old.parent_ino = None;
        fs::write(
            quarantine::meta_path(&cfg, &meta.id),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        quarantine::restore_file(&meta.id, &cfg).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"MZ");
        let _ = fs::remove_dir_all(&root);
    }
}
