//! OS abstraction used by every core module. Each target provides the same function set:
//! discover_watched_dirs, discover_canary_dirs, set_hidden_file, lock_quarantined_file,
//! unlock_restored_file, send_desktop_notification, is_protected_process, is_trusted_binary,
//! path_key, path_is_within, install_service, uninstall_service, run_service,
//! install_ctrlc_handler, detach_console.

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
