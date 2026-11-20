use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use the_nex_core::bin_ai::BinaryAiScanner;
use the_nex_core::config::{self, AppConfig, CliArgs, Engine, Mode, RuntimeToggles};
use the_nex_core::engine;
use the_nex_core::quarantine::{self, Severity, ThreatEvent};
use the_nex_core::{canary, logger, notifier, platform};

fn main() -> ExitCode {
    let args = match config::parse_args(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", config::USAGE);
            return ExitCode::from(2);
        }
    };
    let shutdown = Arc::new(AtomicBool::new(false));

    match &args.mode {
        Mode::Help => {
            println!("{}", config::USAGE);
            ExitCode::SUCCESS
        }
        Mode::Install => report(platform::install_service()),
        Mode::Uninstall => report(platform::uninstall_service()),
        Mode::Restore(id) => restore(id, &args),
        Mode::Delete(id) => delete(id, &args),
        Mode::Set(engine, enabled) => set_toggle(*engine, *enabled, &args),
        Mode::QuickScan => quick_scan(&args),
        Mode::RearmCanaries => rearm_canaries(&args),
        Mode::Notifier => {
            platform::detach_console();
            logger::init_without_file(false);
            let cfg = AppConfig::from_cli(&args);
            notifier::run_notifier(&cfg, shutdown);
            ExitCode::SUCCESS
        }
        Mode::Tray => {
            platform::detach_console();
            logger::init_without_file(false);
            report(platform::run_tray(AppConfig::from_cli(&args)).map(|()| String::new()))
        }
        Mode::Console => {
            platform::install_ctrlc_handler(Arc::clone(&shutdown));
            let cfg = AppConfig::from_cli(&args);
            engine::run(cfg, shutdown);
            ExitCode::SUCCESS
        }
        Mode::Service => {
            let cfg = AppConfig::from_cli(&args);
            logger::init(&cfg.log_dir, false);
            match platform::run_service(shutdown, cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    logger::error(&e);
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn report(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cli_config(args: &CliArgs) -> AppConfig {
    let cfg = AppConfig::from_cli(args);
    logger::init(&cfg.log_dir, true);
    cfg
}

fn restore(id: &str, args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    match quarantine::restore_file(id, &cfg) {
        Ok(meta) => {
            quarantine::record_event(
                &cfg,
                ThreatEvent::new(
                    "QUARANTINE_RESTORE",
                    Severity::Low,
                    meta.original_path.display().to_string(),
                    "RESTORED",
                    format!("id={} sha256={}", meta.id, meta.sha256),
                ),
            );
            println!("Restored {} to {}", meta.id, meta.original_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: restoring {id} failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn delete(id: &str, args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    match quarantine::delete_quarantined_file(id, &cfg) {
        Ok(meta) => {
            quarantine::record_event(
                &cfg,
                ThreatEvent::new(
                    "QUARANTINE_DELETE",
                    Severity::Low,
                    meta.original_path.display().to_string(),
                    "DELETED",
                    format!("id={} sha256={}", meta.id, meta.sha256),
                ),
            );
            println!("Deleted {} ({})", meta.id, meta.original_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: deleting {id} failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn set_toggle(engine: Engine, enabled: bool, args: &CliArgs) -> ExitCode {
    let cfg = AppConfig::from_cli(args);
    let mut toggles = match RuntimeToggles::load(&cfg.settings_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}: {e}", cfg.settings_file.display());
            return ExitCode::FAILURE;
        }
    };
    toggles.set(engine, enabled);
    match toggles.save(&cfg.settings_file) {
        Ok(()) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&toggles).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot write {}: {e}", cfg.settings_file.display());
            ExitCode::FAILURE
        }
    }
}

fn quick_scan(args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    if let Err(e) = cfg.ensure_dirs() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    let scanner = BinaryAiScanner::load(&cfg.model_path).with_max_scan_bytes(cfg.max_ai_scan_bytes);
    let result = engine::run_quick_scan(&cfg, &scanner);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
    ExitCode::SUCCESS
}

fn rearm_canaries(args: &CliArgs) -> ExitCode {
    let cfg = cli_config(args);
    let states = canary::rearm_canaries(&engine::canary_dirs(&cfg));
    println!(
        "{}",
        serde_json::to_string_pretty(&states).unwrap_or_default()
    );
    if states.iter().all(|s| s.is_intact()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
