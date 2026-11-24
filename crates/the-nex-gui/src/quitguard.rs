//! Keeps the menu-bar app alive when its window is closed. Quit-on-last-window utilities send
//! a Quit AppleEvent a few seconds after the window goes away; while the window is hidden such
//! a request from a third-party app is declined. Quit from The Nex's own menu, Cmd-Q, logout,
//! restart and anything Apple-signed (Dock, Activity Monitor, loginwindow) still quit it.

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};

use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{class, msg_send, sel};
use objc2_foundation::NSString;

/// True while the main window is hidden and the app lives only in the menu bar.
pub static IN_MENU_BAR: AtomicBool = AtomicBool::new(false);

const TERMINATE_CANCEL: usize = 0;
const TERMINATE_NOW: usize = 1;
/// keySenderPIDAttr ('spid'): the process that sent the current AppleEvent.
const SENDER_PID: u32 = u32::from_be_bytes(*b"spid");

/// Bundle id of the app that sent the Quit AppleEvent being handled, if it can be identified.
unsafe fn quit_sender() -> Option<String> {
    let manager: *mut AnyObject = msg_send![class!(NSAppleEventManager), sharedAppleEventManager];
    let event: *mut AnyObject = msg_send![manager, currentAppleEvent];
    if event.is_null() {
        return None; // terminate: was called directly (Cmd-Q), not by another app
    }
    let attr: *mut AnyObject = msg_send![event, attributeDescriptorForKeyword: SENDER_PID];
    if attr.is_null() {
        return None;
    }
    let pid: i32 = msg_send![attr, int32Value];
    let app: *mut AnyObject =
        msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier: pid];
    if app.is_null() {
        return None;
    }
    let bundle: *mut NSString = msg_send![app, bundleIdentifier];
    bundle.as_ref().map(|b| b.to_string())
}

fn declines(in_menu_bar: bool, sender: Option<&str>) -> bool {
    in_menu_bar && sender.is_some_and(|s| !s.starts_with("com.apple.") && s != "com.thenex.edr")
}

extern "C-unwind" fn should_terminate(_this: &AnyObject, _cmd: Sel, _app: &AnyObject) -> usize {
    // SAFETY: called by AppKit on the main thread while it handles the terminate request.
    let sender = unsafe { quit_sender() };
    if declines(IN_MENU_BAR.load(Ordering::SeqCst), sender.as_deref()) {
        TERMINATE_CANCEL
    } else {
        TERMINATE_NOW
    }
}

/// Adds `applicationShouldTerminate:` to the app delegate (tao's delegate does not define it).
pub fn install() {
    const TYPES: &CStr = c"Q@:@";
    // SAFETY: runs on the main thread during setup; the method signature matches TYPES.
    unsafe {
        let app: *mut AnyObject = msg_send![class!(NSApplication), sharedApplication];
        let delegate: *mut AnyObject = msg_send![app, delegate];
        if delegate.is_null() {
            return;
        }
        let class = objc2::ffi::object_getClass(delegate) as *mut AnyClass;
        let imp: Imp = std::mem::transmute(
            should_terminate as extern "C-unwind" fn(&AnyObject, Sel, &AnyObject) -> usize,
        );
        objc2::ffi::class_replaceMethod(
            class,
            sel!(applicationShouldTerminate:),
            imp,
            TYPES.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::declines;

    #[test]
    fn only_third_party_quits_are_declined_and_only_in_the_menu_bar() {
        assert!(declines(true, Some("com.vorssaint.utils")));
        assert!(!declines(false, Some("com.vorssaint.utils"))); // window open: quit normally
        assert!(!declines(true, Some("com.apple.loginwindow"))); // logout / restart
        assert!(!declines(true, Some("com.apple.ActivityMonitor")));
        assert!(!declines(true, Some("com.thenex.edr")));
        assert!(!declines(true, None)); // Cmd-Q or an unknown sender
    }
}
