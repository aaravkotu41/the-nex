//! macOS camera permission (TCC). The AegisMesh page uses the camera through the web view,
//! which can only see "denied"; asking AVFoundation first shows the system popup and tells
//! the UI whether to offer the Settings shortcut.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2::{class, msg_send};
use objc2_foundation::NSString;

#[link(name = "AVFoundation", kind = "framework")]
unsafe extern "C" {
    static AVMediaTypeVideo: Option<&'static NSString>;
}

fn media_type() -> Result<&'static NSString, String> {
    // SAFETY: AVMediaTypeVideo is an immutable NSString constant exported by AVFoundation.
    unsafe { AVMediaTypeVideo }.ok_or_else(|| "AVFoundation is unavailable".to_string())
}

/// AVAuthorizationStatus: 0 not determined, 1 restricted, 2 denied, 3 authorized.
fn status() -> Result<isize, String> {
    let video = media_type()?;
    // SAFETY: class method with an NSString argument, returns NSInteger.
    Ok(unsafe { msg_send![class!(AVCaptureDevice), authorizationStatusForMediaType: video] })
}

/// Returns "granted", "denied" or "restricted". Shows the macOS popup when the user has not
/// decided yet; waits up to 2 minutes for the answer.
pub fn ensure_access() -> Result<&'static str, String> {
    match status()? {
        3 => return Ok("granted"),
        2 => return Ok("denied"),
        1 => return Ok("restricted"),
        _ => {}
    }
    let video = media_type()?;
    let (tx, rx) = mpsc::channel();
    let handler = RcBlock::new(move |granted: Bool| {
        let _ = tx.send(granted.as_bool());
    });
    // SAFETY: the completion block is retained by AVFoundation until it runs once.
    let _: () = unsafe {
        msg_send![class!(AVCaptureDevice), requestAccessForMediaType: video, completionHandler: &*handler]
    };
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(true) => Ok("granted"),
        Ok(false) => Ok("denied"),
        Err(_) => Err("No answer to the camera prompt".to_string()),
    }
}

pub fn open_settings() -> Result<(), String> {
    std::process::Command::new("/usr/bin/open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Camera")
        .status()
        .map_err(|e| format!("cannot open System Settings: {e}"))
        .map(|_| ())
}
