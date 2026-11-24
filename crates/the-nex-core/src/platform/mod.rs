//! OS abstraction used by every core module. Each target provides the same function set:
//! discover_watched_dirs, discover_canary_dirs, discover_quick_scan_dirs, set_hidden_file,
//! lock_quarantined_file, unlock_restored_file, send_desktop_notification, is_trusted_binary,
//! path_key, path_is_within, install_service, uninstall_service, service_installed,
//! run_service, run_tray, tray_is_running, run_elevated, install_ctrlc_handler, detach_console.

use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;

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

/// True when a path contains `..`; containment checks reject such paths instead of resolving them.
pub(crate) fn has_parent_dir(path: &std::path::Path) -> bool {
    path.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

pub fn is_protected_process(pid: u32, name: &str) -> bool {
    if matches!(pid, 0 | 1 | 4) || pid == std::process::id() {
        return true;
    }
    let lower = name.to_lowercase();
    PROTECTED_PROCESS_NAMES.contains(&lower.as_str())
}

/// Queues a desktop notification and returns at once. Delivery can block for seconds
/// (macOS notification centre, osascript fallback, WinRT activation), so detectors and the
/// tray's message loop hand it to one background thread instead of waiting. When the queue
/// is full the notification is dropped; the event log always has the record.
pub fn send_desktop_notification_async(title: &str, body: &str) {
    static QUEUE: OnceLock<Option<SyncSender<(String, String)>>> = OnceLock::new();
    let queue = QUEUE.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<(String, String)>(32);
        std::thread::Builder::new()
            .name("thenex-notify".into())
            .spawn(move || {
                for (title, body) in rx {
                    send_desktop_notification(&title, &body);
                }
            })
            .ok()
            .map(|_| tx)
    });
    match queue {
        Some(tx) => {
            let _ = tx.try_send((title.to_string(), body.to_string()));
        }
        None => send_desktop_notification(title, body),
    }
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
    fn parent_dir_detection() {
        assert!(has_parent_dir(std::path::Path::new("a/../b")));
        assert!(!has_parent_dir(std::path::Path::new("a/b..c/d")));
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
