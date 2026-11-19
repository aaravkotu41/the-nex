use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use the_nex::config::{self, AppConfig, CliArgs, Mode};
use the_nex::quarantine::{self, Severity, ThreatEvent};
use the_nex::{engine, logger, notifier, platform};

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
        Mode::Notifier => {
            platform::detach_console();
            logger::init_without_file(false);
            let cfg = AppConfig::from_cli(&args);
            notifier::run_notifier(&cfg, shutdown);
            ExitCode::SUCCESS
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
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn restore(id: &str, args: &CliArgs) -> ExitCode {
    let cfg = AppConfig::from_cli(args);
    logger::init(&cfg.log_dir, true);
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
