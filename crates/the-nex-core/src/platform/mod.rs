//! OS abstraction used by every core module. Each target provides the same function set:
//! discover_watched_dirs, discover_canary_dirs, discover_quick_scan_dirs, set_hidden_file,
//! lock_quarantined_file, unlock_restored_file, send_desktop_notification, is_trusted_binary,
//! path_key, path_is_within, install_service, uninstall_service, service_installed,
//! run_service, run_tray, tray_is_running, run_elevated, install_ctrlc_handler, detach_console.

use std::path::PathBuf;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::*;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use self::macos::*;

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("The Nex implements the platform layer for Windows and macOS only");

pub const DAEMON_EXE_STEM: &str = "the-nex";
pub const GUI_EXE_STEM: &str = "the-nex-gui";

/// Kernel/session-critical processes and The Nex itself; never terminated on either OS.
const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "system",
    "system idle process",
    "idle",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "launchd",
    "kernel_task",
    "windowserver",
    "finder",
    "loginwindow",
    "dock",
    "systemuiserver",
    "the-nex",
    "the-nex.exe",
    "the-nex-gui",
    "the-nex-gui.exe",
];

pub fn is_protected_process(pid: u32, name: &str) -> bool {
    if matches!(pid, 0 | 1 | 4) || pid == std::process::id() {
        return true;
    }
    let lower = name.to_lowercase();
    PROTECTED_PROCESS_NAMES.contains(&lower.as_str())
}

/// Path of a sibling binary installed next to the running executable (the-nex / the-nex-gui).
pub fn sibling_executable(stem: &str) -> PathBuf {
    let file_name = format!("{stem}{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&file_name)))
        .unwrap_or_else(|| PathBuf::from(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_processes_cover_both_platforms() {
        for pid in [0, 1, 4, std::process::id()] {
            assert!(is_protected_process(pid, "anything"), "pid {pid}");
        }
        for name in [
            "the-nex",
            "the-nex.exe",
            "the-nex-gui",
            "Explorer.EXE",
            "svchost.exe",
            "launchd",
            "WindowServer",
        ] {
            assert!(is_protected_process(4242, name), "{name}");
        }
        assert!(!is_protected_process(99999, "malware_sim.exe"));
    }

    #[test]
    fn sibling_executables_live_next_to_the_current_binary() {
        let gui = sibling_executable(GUI_EXE_STEM);
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(gui.parent().unwrap(), exe_dir);
        assert!(gui
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("the-nex-gui"));
    }
}
