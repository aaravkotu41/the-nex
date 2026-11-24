#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod appearance;
#[cfg(target_os = "macos")]
mod camera;
#[cfg(target_os = "macos")]
mod menubar;
#[cfg(target_os = "macos")]
mod quitguard;

use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use the_nex_core::bin_ai::BinaryAiScanner;
use the_nex_core::canary;
use the_nex_core::config::{AppConfig, Engine, RuntimeToggles, ZipLimits};
use the_nex_core::engine::{self, QuickScanReport, ScanKind};
use the_nex_core::platform;
use the_nex_core::quarantine::{self, QuarantineMeta, Severity, ThreatEvent};
use the_nex_core::scan_jobs::{self, ScanProgress};
use the_nex_core::status::{self, CanaryStatus, EngineStatus};

const EVENT_TAIL_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_EVENT_LIMIT: usize = 200;
const MAX_EVENT_LIMIT: usize = 5000;

#[derive(Serialize)]
struct DaemonInfo {
    online: bool,
    pid: Option<u32>,
    version: Option<String>,
    memory_mb: Option<f64>,
    cpu_percent: Option<f32>,
    uptime_seconds: Option<i64>,
}

#[derive(Serialize)]
struct Thresholds {
    max_ratio: f64,
    max_uncompressed_gb: f64,
    max_depth: u32,
    nested_read_mb: f64,
    min_ratio_check_mb: f64,
    ai_threshold: f32,
}

#[derive(Serialize)]
struct DashboardState {
    daemon: DaemonInfo,
    toggles: RuntimeToggles,
    dry_run: bool,
    scanned: u64,
    files_scanned: u64,
    processes_inspected: u64,
    processes_watched: u64,
    threats_detected: u64,
    quarantined: usize,
    canaries: Vec<CanaryStatus>,
    canaries_intact: usize,
    model_path: String,
    model_present: bool,
    model_loaded: bool,
    watched_dirs: Vec<String>,
    data_dir: String,
    events_log: String,
    settings_file: String,
    service_installed: bool,
    thresholds: Thresholds,
    platform: &'static str,
}

fn config() -> AppConfig {
    AppConfig::system()
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn fresh_status(cfg: &AppConfig) -> Option<EngineStatus> {
    status::read_status(&cfg.status_file).filter(EngineStatus::is_fresh)
}

fn is_permission_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

/// Runs `the-nex <args>` through the OS administrator prompt: the root-only engine copy once the
/// service is installed (the app's own copy may be user-writable), the app's copy to install it.
fn elevated(args: &[&str]) -> Result<(), String> {
    let engine = config()
        .base_dir
        .join("engine")
        .join(platform::DAEMON_EXE_STEM);
    let exe = if cfg!(target_os = "macos") && args.first() != Some(&"--install") && engine.is_file()
    {
        engine
    } else {
        platform::sibling_executable(platform::DAEMON_EXE_STEM)
    };
    if !exe.is_file() {
        return Err(format!("{} was not found next to the app", exe.display()));
    }
    // macOS shows this sentence in the admin prompt, so a script can't hide what it asks for.
    #[cfg(target_os = "macos")]
    let status = {
        let action = match args.first().copied() {
            Some("--install") => "install its background protection service".to_string(),
            Some("--uninstall") => "REMOVE its background protection service".to_string(),
            Some("--set") => format!("change an engine setting ({})", args[1..].join(" ")),
            Some("--quick-scan") => "run a quick scan".to_string(),
            Some("--restore") => "restore a file from quarantine".to_string(),
            Some("--delete") => "permanently delete a quarantined file".to_string(),
            Some("--rearm-canaries") => "re-create its ransomware decoy files".to_string(),
            _ => format!("run: the-nex {}", args.join(" ")),
        };
        platform::run_elevated_with_prompt(&exe, args, &format!("The Nex wants to {action}."))?
    };
    #[cfg(not(target_os = "macos"))]
    let status = platform::run_elevated(&exe, args)?;
    match status {
        0 => Ok(()),
        code => Err(format!(
            "the-nex {} exited with code {code}",
            args.join(" ")
        )),
    }
}

async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| e.to_string())?
}

fn daemon_info(status: Option<&EngineStatus>) -> DaemonInfo {
    match status {
        Some(s) => DaemonInfo {
            online: true,
            pid: Some(s.pid),
            version: Some(s.version.clone()),
            memory_mb: Some(s.usage.memory_bytes as f64 / (1024.0 * 1024.0)),
            cpu_percent: Some(s.usage.cpu_percent),
            uptime_seconds: Some((Utc::now() - s.started_at).num_seconds()),
        },
        None => DaemonInfo {
            online: false,
            pid: None,
            version: None,
            memory_mb: None,
            cpu_percent: None,
            uptime_seconds: None,
        },
    }
}

fn quarantine_records(
    cfg: &AppConfig,
    status: Option<&EngineStatus>,
) -> Result<Vec<QuarantineMeta>, String> {
    match quarantine::list_quarantined(cfg) {
        Ok(records) => Ok(records),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) if is_permission_error(&e) => status
            .map(|s| s.quarantine.clone())
            .or_else(|| status::read_status(&cfg.status_file).map(|s| s.quarantine))
            .ok_or_else(|| {
                "the quarantine folder needs administrator rights and the service is not running"
                    .to_string()
            }),
        Err(e) => Err(e.to_string()),
    }
}

/// Unreadable slots (other users' folders) take the daemon's own view when it is running.
fn merged_canaries(cfg: &AppConfig, status: Option<&EngineStatus>) -> Vec<CanaryStatus> {
    let local = canary::canary_states(&engine::canary_dirs(cfg));
    let Some(status) = status else {
        return local;
    };
    if local.is_empty() {
        return status.canaries.clone();
    }
    local
        .into_iter()
        .map(|entry| {
            if entry.state == "Unreadable" {
                status
                    .canaries
                    .iter()
                    .find(|c| c.path == entry.path)
                    .cloned()
                    .unwrap_or(entry)
            } else {
                entry
            }
        })
        .collect()
}

#[tauri::command]
fn get_dashboard_state() -> Result<DashboardState, String> {
    let cfg = config();
    let status = fresh_status(&cfg);
    let toggles = RuntimeToggles::load(&cfg.settings_file).map_err(|e| e.to_string())?;
    let canaries = merged_canaries(&cfg, status.as_ref());
    let quarantined = quarantine_records(&cfg, status.as_ref())
        .map(|records| records.len())
        .unwrap_or(0);
    let limits = ZipLimits::default();
    let mb = 1024.0 * 1024.0;
    let watched_dirs = match &status {
        Some(s) if !s.watched_dirs.is_empty() => {
            s.watched_dirs.iter().map(|d| display(d)).collect()
        }
        _ => platform::discover_watched_dirs()
            .iter()
            .map(|d| display(d))
            .collect(),
    };
    Ok(DashboardState {
        daemon: daemon_info(status.as_ref()),
        dry_run: status
            .as_ref()
            .map(|s| s.dry_run)
            .unwrap_or(toggles.dry_run),
        toggles,
        scanned: status.as_ref().map(EngineStatus::scanned).unwrap_or(0),
        files_scanned: status.as_ref().map(|s| s.files_scanned).unwrap_or(0),
        processes_inspected: status.as_ref().map(|s| s.processes_inspected).unwrap_or(0),
        processes_watched: status.as_ref().map(|s| s.processes_watched).unwrap_or(0),
        threats_detected: status.as_ref().map(|s| s.threats_detected).unwrap_or(0),
        quarantined,
        canaries_intact: canaries.iter().filter(|c| c.is_intact()).count(),
        canaries,
        model_present: cfg.model_path.is_file(),
        model_loaded: status.as_ref().map(|s| s.model_loaded).unwrap_or(false),
        model_path: display(&cfg.model_path),
        watched_dirs,
        data_dir: display(&cfg.base_dir),
        events_log: display(&cfg.events_log),
        settings_file: display(&cfg.settings_file),
        service_installed: platform::service_installed(),
        thresholds: Thresholds {
            max_ratio: limits.max_ratio,
            max_uncompressed_gb: limits.max_uncompressed_bytes as f64 / (mb * 1024.0),
            max_depth: limits.max_depth,
            nested_read_mb: limits.max_nested_mem_read as f64 / mb,
            min_ratio_check_mb: limits.min_ratio_check_bytes as f64 / mb,
            ai_threshold: cfg.ai_threshold,
        },
        platform: std::env::consts::OS,
    })
}

fn event_matches(event: &ThreatEvent, query: &str, severity: Option<Severity>) -> bool {
    if severity.is_some_and(|s| event.severity != s) {
        return false;
    }
    if query.is_empty() {
        return true;
    }
    [
        event.threat_type.as_str(),
        event.target.as_str(),
        event.action_taken.as_str(),
        event.details.as_str(),
        event.id.as_str(),
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(query))
}

#[tauri::command]
fn get_events(
    limit: Option<usize>,
    query: Option<String>,
    severity: Option<String>,
) -> Result<Vec<ThreatEvent>, String> {
    let cfg = config();
    let events = match quarantine::read_recent_events(&cfg.events_log, EVENT_TAIL_BYTES) {
        Ok(events) => events,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", cfg.events_log.display())),
    };
    let query = query.unwrap_or_default().trim().to_lowercase();
    let severity = match severity.as_deref().map(str::to_ascii_uppercase).as_deref() {
        None | Some("") | Some("ALL") => None,
        Some("LOW") => Some(Severity::Low),
        Some("MEDIUM") => Some(Severity::Medium),
        Some("HIGH") => Some(Severity::High),
        Some("CRITICAL") => Some(Severity::Critical),
        Some(other) => return Err(format!("unknown severity: {other}")),
    };
    let limit = limit
        .unwrap_or(DEFAULT_EVENT_LIMIT)
        .clamp(1, MAX_EVENT_LIMIT);
    Ok(events
        .into_iter()
        .filter(|e| event_matches(e, &query, severity))
        .take(limit)
        .collect())
}

#[tauri::command]
async fn toggle_engine(engine: String, enabled: bool) -> Result<RuntimeToggles, String> {
    blocking(move || {
        let engine = Engine::parse(&engine).ok_or_else(|| format!("unknown engine: {engine}"))?;
        let cfg = config();
        let mut toggles = RuntimeToggles::load(&cfg.settings_file).map_err(|e| e.to_string())?;
        toggles.set(engine, enabled);
        match toggles.save(&cfg.settings_file) {
            Ok(()) => Ok(toggles),
            Err(e) if is_permission_error(&e) => {
                let switch = format!("{}={}", engine.key(), if enabled { "on" } else { "off" });
                elevated(&["--set", switch.as_str()])?;
                RuntimeToggles::load(&cfg.settings_file).map_err(|e| e.to_string())
            }
            Err(e) => Err(format!("{}: {e}", cfg.settings_file.display())),
        }
    })
    .await
}

/// True when this process may write to `dir` (creating it if needed).
fn writable(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".thenex-gui-probe-{}", std::process::id()));
    let ok = fs::write(&probe, b"probe").is_ok();
    let _ = fs::remove_file(&probe);
    ok
}

/// Message for remote (synced) commands that would need an administrator prompt.
const NEEDS_LOCAL: &str = "Needs local approval: open The Nex on this computer";

static SCAN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Shared by the `run_quick_scan` command and the macOS menu bar; blocks until the scan ends.
/// Only one scan runs at a time. A `remote` caller never triggers an admin prompt.
const SCAN_BUSY: &str = scan_jobs::BUSY;
const QUICK_SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// The running service does on-demand scans itself: no password prompt, and on macOS it is the
/// process that holds Full Disk Access.
fn service_scans(cfg: &AppConfig) -> bool {
    fresh_status(cfg).is_some() && scan_jobs::available(cfg)
}

/// Whole-disk, report-only scan. Returns at once; the UI follows `scan_progress`.
#[tauri::command]
async fn start_full_scan() -> Result<(), String> {
    blocking(|| {
        let cfg = config();
        if !service_scans(&cfg) {
            return Err(
                "A full scan is run by the background service. Install or restart it in Settings, then try again."
                    .to_string(),
            );
        }
        scan_jobs::request(&cfg, ScanKind::Full)
    })
    .await
}

/// Live progress of the service's current scan; `running` is false once it stops updating.
#[tauri::command]
fn scan_progress() -> Option<ScanProgress> {
    scan_jobs::read_progress(&config()).map(|p| ScanProgress {
        running: p.is_live(),
        ..p
    })
}

#[tauri::command]
fn cancel_scan() -> Result<(), String> {
    scan_jobs::request_cancel(&config())
}

#[tauri::command]
fn last_full_scan() -> Option<QuickScanReport> {
    engine::read_scan_report(&config(), ScanKind::Full)
}

fn quick_scan(remote: bool) -> Result<QuickScanReport, String> {
    let _guard = match SCAN_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return Err(SCAN_BUSY.into()),
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
    };
    let cfg = config();
    if service_scans(&cfg) {
        return scan_jobs::request_and_wait(&cfg, ScanKind::Quick, QUICK_SCAN_WAIT);
    }
    if writable(&cfg.quarantine_dir) && writable(&cfg.log_dir) {
        let scanner =
            BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
        return Ok(engine::run_quick_scan(&cfg, &scanner));
    }
    if remote {
        return Err(NEEDS_LOCAL.to_string());
    }
    let before = engine::read_last_quick_scan(&cfg);
    elevated(&["--quick-scan"])?;
    match engine::read_last_quick_scan(&cfg) {
        Some(report) if Some(&report) != before.as_ref() => Ok(report),
        _ => Err("the quick scan finished but its report could not be read".to_string()),
    }
}

#[tauri::command]
async fn run_quick_scan(remote: Option<bool>) -> Result<QuickScanReport, String> {
    blocking(move || quick_scan(remote == Some(true))).await
}

#[tauri::command]
fn list_quarantine() -> Result<Vec<QuarantineMeta>, String> {
    let cfg = config();
    let status = fresh_status(&cfg);
    quarantine_records(&cfg, status.as_ref())
}

fn audit(cfg: &AppConfig, threat_type: &str, action: &str, meta: &QuarantineMeta) {
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            threat_type,
            Severity::Low,
            display(&meta.original_path),
            action,
            format!("id={} sha256={} via desktop app", meta.id, meta.sha256),
        ),
    );
}

#[tauri::command]
async fn restore_quarantine(id: String) -> Result<String, String> {
    blocking(move || {
        if !quarantine::is_valid_id(&id) {
            return Err(format!("invalid quarantine ID: {id}"));
        }
        let cfg = config();
        match quarantine::restore_file(&id, &cfg) {
            Ok(meta) => {
                audit(&cfg, "QUARANTINE_RESTORE", "RESTORED", &meta);
                Ok(format!("Restored to {}", meta.original_path.display()))
            }
            Err(e) if is_permission_error(&e) => {
                elevated(&["--restore", id.as_str()])?;
                Ok(format!("Restored {id}"))
            }
            Err(e) => Err(e.to_string()),
        }
    })
    .await
}

#[tauri::command]
async fn delete_quarantine(id: String) -> Result<String, String> {
    blocking(move || {
        if !quarantine::is_valid_id(&id) {
            return Err(format!("invalid quarantine ID: {id}"));
        }
        let cfg = config();
        match quarantine::delete_quarantined_file(&id, &cfg) {
            Ok(meta) => {
                audit(&cfg, "QUARANTINE_DELETE", "DELETED", &meta);
                Ok(format!("Deleted {}", meta.id))
            }
            Err(e) if is_permission_error(&e) => {
                elevated(&["--delete", id.as_str()])?;
                Ok(format!("Deleted {id}"))
            }
            Err(e) => Err(e.to_string()),
        }
    })
    .await
}

#[tauri::command]
async fn verify_canaries(remote: Option<bool>) -> Result<Vec<CanaryStatus>, String> {
    blocking(move || {
        let cfg = config();
        let dirs: Vec<PathBuf> = engine::canary_dirs(&cfg);
        if dirs.is_empty() {
            return Ok(Vec::new());
        }
        let report = canary::rearm_canaries(&dirs);
        if !report.iter().all(CanaryStatus::is_intact) {
            if remote == Some(true) {
                return Err(NEEDS_LOCAL.to_string());
            }
            elevated(&["--rearm-canaries"])?;
        }
        Ok(merged_canaries(&cfg, fresh_status(&cfg).as_ref()))
    })
    .await
}

#[tauri::command]
async fn install_service() -> Result<String, String> {
    blocking(|| {
        elevated(&["--install"])?;
        Ok("The Nex background service is installed and starts automatically.".to_string())
    })
    .await
}

#[tauri::command]
async fn uninstall_service() -> Result<String, String> {
    blocking(|| {
        elevated(&["--uninstall"])?;
        Ok("The Nex background service has been removed.".to_string())
    })
    .await
}

/// Camera permission for the AegisMesh page: "granted", "denied" or "restricted".
/// Shows the macOS camera popup if the user has not answered it yet.
#[tauri::command]
async fn camera_access() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return blocking(|| camera::ensure_access().map(str::to_string)).await;
    #[cfg(not(target_os = "macos"))]
    Ok("granted".to_string())
}

#[tauri::command]
async fn open_camera_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return blocking(camera::open_settings).await;
    #[cfg(not(target_os = "macos"))]
    Err("Open your system camera settings and allow The Nex.".to_string())
}

/// The embedded AegisMesh console (ui/aegismesh) calls this through the parent window.
/// Every operation is a local, in-memory simulation in aegismesh-core.
#[tauri::command]
async fn aegismesh(op: String, request: serde_json::Value) -> Result<serde_json::Value, String> {
    aegismesh_core::console::handle(&op, &request)
}

fn main() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder
        .setup(menubar::setup)
        .on_window_event(menubar::on_window_event);
    let app = builder
        .register_uri_scheme_protocol(appearance::WALLPAPER_SCHEME, |ctx, request| {
            appearance::serve_wallpaper(ctx.app_handle(), &request)
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard_state,
            get_events,
            toggle_engine,
            run_quick_scan,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            verify_canaries,
            install_service,
            uninstall_service,
            appearance::get_appearance,
            appearance::save_appearance,
            appearance::resolve_wallpaper_url,
            appearance::download_wallpaper,
            appearance::save_wallpaper_file,
            aegismesh,
            camera_access,
            open_camera_settings,
            start_full_scan,
            scan_progress,
            cancel_scan,
            last_full_scan
        ])
        .build(tauri::generate_context!())
        .expect("failed to start The Nex desktop app");
    app.run(|_app, _event| {
        #[cfg(target_os = "macos")]
        menubar::on_run_event(_app, &_event);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, severity: Severity, target: &str) -> ThreatEvent {
        ThreatEvent::new(kind, severity, target, "QUARANTINED id=abc", "ratio 1028:1")
    }

    #[test]
    fn events_filter_by_query_and_severity() {
        let zip = event(
            "ZIP_BOMB",
            Severity::High,
            r"C:\Users\x\Downloads\invoice_pack.zip",
        );
        let lotl = event("LOTL_SCRIPT", Severity::High, "powershell.exe (pid 8842)");
        assert!(event_matches(&zip, "invoice", None));
        assert!(event_matches(&zip, "1028", Some(Severity::High)));
        assert!(!event_matches(&zip, "invoice", Some(Severity::Low)));
        assert!(event_matches(&lotl, "8842", None));
        assert!(!event_matches(&lotl, "invoice", None));
        assert!(event_matches(&lotl, "", None));
    }

    #[test]
    fn offline_daemon_reports_no_figures() {
        let info = daemon_info(None);
        assert!(!info.online && info.pid.is_none() && info.memory_mb.is_none());
    }
}
