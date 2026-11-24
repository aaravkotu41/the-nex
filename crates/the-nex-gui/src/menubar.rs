//! macOS menu-bar item. Windows already has the daemon's `--tray` notification-area icon.

use std::time::Duration;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{ActivationPolicy, App, AppHandle, Emitter, Manager, RunEvent, WindowEvent, Wry};

// Each refresh reads canaries and quarantine; 15 s keeps the menu current without busy work.
const STATUS_REFRESH: Duration = Duration::from_secs(15);

fn status_text() -> String {
    let Ok(state) = crate::get_dashboard_state() else {
        return "Engine service offline".into();
    };
    let t = &state.toggles;
    let on = [
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
    } else if on == 4 {
        "Protected · 4 of 4 engines on".into()
    } else {
        format!("Partial protection · {on} of 4 engines on")
    }
}

fn scan_text(report: Result<the_nex_core::engine::QuickScanReport, String>) -> String {
    match report {
        // Errors can hold long paths; keep the menu narrow (full text is in the dashboard).
        Err(e) if e.chars().count() > 48 => {
            format!(
                "Last scan failed: {}…",
                e.chars().take(48).collect::<String>()
            )
        }
        Err(e) => format!("Last scan failed: {e}"),
        Ok(r) if r.findings.is_empty() => format!(
            "Last scan: no threats · {} files · {:.1} s",
            r.files_scanned,
            r.duration_ms as f64 / 1000.0
        ),
        Ok(r) => format!("Last scan: {} threats found", r.findings.len()),
    }
}

pub fn setup(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
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
            page @ ("activity" | "quarantine" | "settings") => {
                show_main(app);
                let _ = app.emit("menubar://navigate", page);
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
        let _ = last_scan.set_text(scan_text(crate::quick_scan(false)));
        let _ = status.set_text(status_text());
        let _ = scan.set_text("Quick Scan");
        let _ = scan.set_enabled(true);
        let _ = app.emit("menubar://refresh", ());
    });
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = app.set_activation_policy(ActivationPolicy::Regular);
        let _ = window.unminimize();
        let _ = window.show();
        // From Accessory the app is not frontmost; set_focus on the window activates it.
        let _ = window.set_focus();
    }
}

/// Closing the window hides it so the app stays alive in the menu bar.
pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        if window.label() != "main" {
            return;
        }
        api.prevent_close();
        let _ = window.hide();
        // Leave the Dock while hidden: a pure menu-bar app, which window-closing quit
        // utilities (e.g. Vorssaint) leave running. show_main() restores the Dock icon.
        let _ = window
            .app_handle()
            .set_activation_policy(ActivationPolicy::Accessory);
    }
}

/// Dock-icon click re-shows the hidden window.
pub fn on_run_event(app: &AppHandle, event: &RunEvent) {
    if let RunEvent::Reopen { .. } = event {
        show_main(app);
    }
}
