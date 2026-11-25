//! macOS menu-bar item. Windows already has the daemon's `--tray` notification-area icon.

use std::sync::atomic::Ordering;
use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{
    ActivationPolicy, App, AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder,
    WindowEvent, Wry,
};

use crate::quitguard::IN_MENU_BAR;

// Each refresh reads canaries and quarantine; 15 s keeps the menu current without busy work.
const STATUS_REFRESH: Duration = Duration::from_secs(15);

fn status_text() -> String {
    let Ok(state) = crate::get_dashboard_state() else {
        return "Engine service offline".into();
    };
    let t = &state.toggles;
    let on = [
        t.known_bad_enabled,
        t.zip_bomb_enabled,
        t.bin_ai_enabled,
        t.process_guard_enabled,
        t.canary_enabled,
    ]
    .iter()
    .filter(|e| **e)
    .count();
    if !state.daemon.online {
        "Engine service offline".into()
    } else if state.dry_run {
        "Dry run · detecting only".into()
    } else if on == 5 && !state.known_bad.loaded {
        "Partial protection · no malware list".into()
    } else if on == 5 {
        "Protected · 5 of 5 engines on".into()
    } else {
        format!("Partial protection · {on} of 5 engines on")
    }
}

fn scan_text(report: Result<the_nex_core::engine::QuickScanReport, String>) -> String {
    match report {
        // Errors can hold long paths; cap the menu width (full text is in the dashboard).
        Err(e) if e.chars().count() > 90 => {
            format!(
                "Last scan failed: {}…",
                e.chars().take(90).collect::<String>()
            )
        }
        Err(e) => format!("Last scan failed: {e}"),
        Ok(r) if !r.unreadable.is_empty() => format!(
            "Last scan: macOS blocked {} folder(s) · open The Nex",
            r.unreadable.len()
        ),
        Ok(r) if r.findings.is_empty() && r.files_examined == 0 && r.never_scan > 0 => {
            "Last scan: nothing checked (all on your never-scan list)".to_string()
        }
        Ok(r) if r.findings.is_empty() => format!(
            "Last scan: no threats · {} files · {:.1} s",
            r.files_scanned,
            r.duration_ms as f64 / 1000.0
        ),
        Ok(r) => format!("Last scan: {} threats found", r.findings.len()),
    }
}

pub fn setup(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    crate::quitguard::install();
    let status = MenuItem::with_id(app, "status", "Checking…", false, None::<&str>)?;
    let last_scan = MenuItem::with_id(app, "last_scan", "No scan run yet", false, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Quick Scan", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &last_scan,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open", "Open The Nex", true, None::<&str>)?,
            &scan,
            &MenuItem::with_id(app, "fullscan", "Full Scan", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "activity", "Activity", true, None::<&str>)?,
            &MenuItem::with_id(app, "quarantine", "Quarantine", true, None::<&str>)?,
            &MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Quit The Nex", true, None::<&str>)?,
        ],
    )?;

    let ticking = status.clone();
    std::thread::spawn(move || loop {
        let _ = ticking.set_text(status_text());
        std::thread::sleep(STATUS_REFRESH);
    });

    TrayIconBuilder::new()
        .icon(Image::from_bytes(include_bytes!(
            "../icons/tray-template.png"
        ))?)
        .icon_as_template(true)
        .tooltip("The Nex")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "scan" => quick_scan(app, &scan, &status, &last_scan),
            page @ ("activity" | "quarantine" | "settings" | "fullscan") => {
                open_main(app, Some(page))
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn quick_scan(
    app: &AppHandle,
    scan: &MenuItem<Wry>,
    status: &MenuItem<Wry>,
    last_scan: &MenuItem<Wry>,
) {
    let _ = scan.set_enabled(false);
    let _ = scan.set_text("Scanning…");
    let (app, scan, status, last_scan) =
        (app.clone(), scan.clone(), status.clone(), last_scan.clone());
    std::thread::spawn(move || {
        let result = crate::quick_scan(false);
        // A scan started from the dashboard is still running: keep the previous result line.
        if result.as_ref().err().map(String::as_str) != Some(crate::SCAN_BUSY) {
            let _ = last_scan.set_text(scan_text(result));
        }
        let _ = status.set_text(status_text());
        let _ = scan.set_text("Quick Scan");
        let _ = scan.set_enabled(true);
        let _ = app.emit("menubar://refresh", ());
    });
}

pub fn show_main(app: &AppHandle) {
    open_main(app, None);
}

/// Shows the main window, building it again if it was closed; `page` opens a dashboard page.
fn open_main(app: &AppHandle, page: Option<&str>) {
    IN_MENU_BAR.store(false, Ordering::SeqCst);
    let _ = app.set_activation_policy(ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        if let Some(page) = page {
            let _ = app.emit("menubar://navigate", page);
        }
        return;
    }
    let Some(mut config) = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == "main")
        .cloned()
    else {
        return;
    };
    // A fresh page has no listener yet, so it reads the page from its address (app.js).
    if let Some(page) = page {
        config.url = WebviewUrl::App(format!("index.html#{page}").into());
    }
    match WebviewWindowBuilder::from_config(app, &config).and_then(|b| b.build()) {
        // From Accessory the app is not frontmost; set_focus on the window activates it.
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(e) => {
            // No window: go back to being a menu-bar app instead of an empty Dock icon.
            eprintln!("The Nex could not reopen its window: {e}");
            IN_MENU_BAR.store(true, Ordering::SeqCst);
            let _ = app.set_activation_policy(ActivationPolicy::Accessory);
        }
    }
}

/// Closing the window really closes it, which frees the web view's memory (~160 MB). The app
/// stays in the menu bar (see on_run_event) and open_main() builds the window again.
pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { .. } = event {
        if window.label() != "main" {
            return;
        }
        IN_MENU_BAR.store(true, Ordering::SeqCst);
        // Leave the Dock while closed; open_main() restores the Dock icon.
        let _ = window
            .app_handle()
            .set_activation_policy(ActivationPolicy::Accessory);
    }
}

/// Dock-icon click re-shows the hidden window.
pub fn on_run_event(app: &AppHandle, event: &RunEvent) {
    // thenex:// links (from the email-confirmed page) only bring the window forward;
    // the URL itself is ignored so a web page can never pass data into the app.
    if matches!(event, RunEvent::Reopen { .. } | RunEvent::Opened { .. }) {
        show_main(app);
    }
    // Closing the last window is not quitting: stay in the menu bar. The menu's Quit passes an
    // exit code and still exits; quit requests from other apps go through quitguard.
    if let RunEvent::ExitRequested {
        code: None, api, ..
    } = event
    {
        if IN_MENU_BAR.load(Ordering::SeqCst) {
            api.prevent_exit();
        }
    }
}
