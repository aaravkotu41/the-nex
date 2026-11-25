//! Scheduled scans: the setting, when a scan is due, and the record of the last one.
//!
//! The service checks once a second (`Scheduler::tick`). A scheduled scan never acts on what it
//! finds (see `ScanKind::Scheduled`), and only the local `--set scan_schedule=...` path or the
//! app's own settings command changes the setting: nothing a remote command can reach.

use crate::bin_ai::BinaryAiScanner;
use crate::config::{write_atomic, AppConfig};
use crate::engine::ScanKind;
use crate::logger;
use crate::scan_jobs::ScanJobs;
use crate::status::Telemetry;
use chrono::{DateTime, Duration as Span, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const STATE_FILE: &str = "scheduled_scan.json";
/// Wait after the service starts, or the schedule is switched on, before the first scan: a
/// scan the moment the Mac wakes or the switch is flipped would be a surprise.
const QUIET: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanSchedule {
    #[default]
    Off,
    Daily,
    Weekly,
}

impl ScanSchedule {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            _ => None,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        }
    }

    pub fn from_u8(n: u8) -> Self {
        match n {
            1 => Self::Daily,
            2 => Self::Weekly,
            _ => Self::Off,
        }
    }

    pub fn interval(self) -> Option<Span> {
        match self {
            Self::Off => None,
            Self::Daily => Some(Span::days(1)),
            Self::Weekly => Some(Span::days(7)),
        }
    }
}

/// Any value that is not a known name means off, so a settings file from a newer version (or
/// a typo) never stops the engines from loading.
pub fn lenient<'de, D: Deserializer<'de>>(d: D) -> Result<ScanSchedule, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(value
        .as_str()
        .and_then(ScanSchedule::parse)
        .unwrap_or_default())
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ScheduleState {
    pub last_run: Option<DateTime<Utc>>,
    /// Quiet wait in seconds, honoured only by a console run (the live check): the installed
    /// service always waits the full ten minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_secs: Option<u64>,
}

fn state_path(cfg: &AppConfig) -> PathBuf {
    cfg.base_dir.join(STATE_FILE)
}

/// Missing or damaged means "never ran": the next scan then waits the quiet period and
/// rewrites the file.
pub fn read_state(cfg: &AppConfig) -> ScheduleState {
    fs::read(state_path(cfg))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Wait,
    Run,
    /// The last run is in the future (clock set back, or a damaged file): record `now` instead,
    /// or no scan would run until the clock caught up.
    ResetClock,
}

/// `settled`: the quiet period since start (or since the schedule was switched on) is over.
/// A scan runs once when `interval` has passed since the last one, however long ago that was
/// (one catch-up, never one per missed day); the caller records the run, which ends the loop.
pub fn verdict(
    schedule: ScanSchedule,
    now: DateTime<Utc>,
    last_run: Option<DateTime<Utc>>,
    settled: bool,
) -> Verdict {
    let Some(interval) = schedule.interval() else {
        return Verdict::Wait;
    };
    match last_run {
        Some(last) if last > now => Verdict::ResetClock,
        _ if !settled => Verdict::Wait,
        Some(last) if now - last < interval => Verdict::Wait,
        _ => Verdict::Run,
    }
}

pub struct Scheduler {
    state: ScheduleState,
    quiet: Duration,
    /// When the schedule was first seen on; None while it is off.
    armed: Option<Instant>,
}

impl Scheduler {
    pub fn load(cfg: &AppConfig) -> Self {
        let state = read_state(cfg);
        let quiet = match (cfg.interactive, state.quiet_secs) {
            (true, Some(secs)) => Duration::from_secs(secs),
            _ => QUIET,
        };
        Self {
            state,
            quiet,
            armed: None,
        }
    }

    /// Called about once a second by the service. Starts nothing while another scan runs.
    pub fn tick(
        &mut self,
        cfg: &Arc<AppConfig>,
        jobs: &Arc<ScanJobs>,
        scanner: &Arc<BinaryAiScanner>,
        telemetry: &Arc<Telemetry>,
    ) {
        let schedule = cfg.toggles.scan_schedule();
        if schedule == ScanSchedule::Off {
            self.armed = None;
            return;
        }
        let armed = *self.armed.get_or_insert_with(Instant::now);
        let now = Utc::now();
        let settled = armed.elapsed() >= self.quiet;
        match verdict(schedule, now, self.state.last_run, settled) {
            Verdict::Wait => {}
            Verdict::ResetClock => self.record(cfg, now),
            Verdict::Run => {
                if jobs.start(ScanKind::Scheduled, cfg, scanner, telemetry) {
                    self.record(cfg, now);
                }
            }
        }
    }

    /// Kept in memory too, so a data folder that cannot be written still runs once, not forever.
    fn record(&mut self, cfg: &AppConfig, now: DateTime<Utc>) {
        self.state.last_run = Some(now);
        let saved = serde_json::to_vec_pretty(&self.state)
            .map_err(std::io::Error::other)
            .and_then(|json| write_atomic(&state_path(cfg), &json));
        if let Err(e) = saved {
            logger::warn(format!("cannot record the scheduled scan: {e}"));
        }
    }
}

/// Runs low on the CPU and disk for the scan's own thread, which ends with the scan.
pub fn lower_priority() {
    #[cfg(target_os = "macos")]
    // SAFETY: plain call that changes only the calling thread.
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    // SAFETY: who = 0 is the calling thread on Linux.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
    #[cfg(windows)]
    // SAFETY: plain calls on the current thread's own pseudo-handle.
    unsafe {
        use windows_sys::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
        };
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Engine;
    use crate::known_bad;
    use chrono::TimeZone;

    const DAY: i64 = 86_400;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn off_never_runs_and_a_first_run_waits_for_the_quiet_period() {
        assert_eq!(verdict(ScanSchedule::Off, at(0), None, true), Verdict::Wait);
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), None, false),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), None, true),
            Verdict::Run
        );
    }

    #[test]
    fn a_scan_is_due_exactly_one_interval_after_the_last() {
        let last = Some(at(0));
        for (schedule, interval) in [(ScanSchedule::Daily, DAY), (ScanSchedule::Weekly, 7 * DAY)] {
            assert_eq!(
                verdict(schedule, at(interval - 1), last, true),
                Verdict::Wait
            );
            assert_eq!(verdict(schedule, at(interval), last, true), Verdict::Run);
            assert_eq!(
                verdict(schedule, at(interval + 1), last, true),
                Verdict::Run
            );
        }
        // Switched from daily to weekly: the last run counts against the longer interval.
        assert_eq!(
            verdict(ScanSchedule::Weekly, at(3 * DAY), last, true),
            Verdict::Wait
        );
    }

    #[test]
    fn a_long_absence_gives_one_catch_up_run_not_one_per_missed_day() {
        let mut last = Some(at(0));
        let now = at(90 * DAY);
        assert_eq!(verdict(ScanSchedule::Daily, now, last, true), Verdict::Run);
        last = Some(now); // what the scheduler records when it starts the scan
        assert_eq!(verdict(ScanSchedule::Daily, now, last, true), Verdict::Wait);
        assert_eq!(
            verdict(ScanSchedule::Daily, at(91 * DAY - 1), last, true),
            Verdict::Wait
        );
    }

    #[test]
    fn a_clock_set_back_resets_instead_of_waiting_for_the_future_or_looping() {
        // Last run recorded "tomorrow" (clock set back, or a damaged file): reset at once, even
        // inside the quiet period, then the normal interval applies from now.
        for settled in [false, true] {
            assert_eq!(
                verdict(ScanSchedule::Daily, at(0), Some(at(DAY)), settled),
                Verdict::ResetClock
            );
        }
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), Some(at(0)), true),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Off, at(0), Some(at(DAY)), true),
            Verdict::Wait
        );
    }

    #[test]
    fn unknown_or_odd_values_mean_off_and_names_parse() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default, deserialize_with = "lenient")]
            s: ScanSchedule,
        }
        let read = |json: &str| serde_json::from_str::<Holder>(json).unwrap().s;
        assert_eq!(read(r#"{"s":"weekly"}"#), ScanSchedule::Weekly);
        assert_eq!(read(r#"{"s":"hourly"}"#), ScanSchedule::Off);
        assert_eq!(read(r#"{"s":7}"#), ScanSchedule::Off);
        assert_eq!(read(r#"{"s":null}"#), ScanSchedule::Off);
        assert_eq!(read("{}"), ScanSchedule::Off);
        assert_eq!(ScanSchedule::parse(" Daily "), Some(ScanSchedule::Daily));
        assert_eq!(ScanSchedule::parse("monthly"), None);
        assert_eq!(
            serde_json::to_string(&ScanSchedule::Daily).unwrap(),
            "\"daily\""
        );
    }

    #[test]
    fn a_damaged_or_missing_state_file_means_never_ran() {
        let dir = std::env::temp_dir().join(format!("thenex-sched-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = AppConfig::for_base_dir(&dir);
        assert_eq!(read_state(&cfg), ScheduleState::default());
        fs::create_dir_all(&dir).unwrap();
        fs::write(state_path(&cfg), b"{ not json").unwrap();
        assert_eq!(read_state(&cfg), ScheduleState::default());
        fs::write(state_path(&cfg), br#"{"last_run":"yesterday-ish"}"#).unwrap();
        assert_eq!(read_state(&cfg), ScheduleState::default());
        // The shortened quiet wait is for console runs only; the service always waits ten minutes.
        fs::write(state_path(&cfg), br#"{"quiet_secs":1}"#).unwrap();
        assert_eq!(Scheduler::load(&cfg).quiet, QUIET);
        let mut console = cfg.clone();
        console.interactive = true;
        assert_eq!(Scheduler::load(&console).quiet, Duration::from_secs(1));
        let mut scheduler = Scheduler::load(&cfg);
        scheduler.record(&cfg, at(5));
        assert_eq!(read_state(&cfg).last_run, Some(at(5)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scheduled_scan_only_reports_runs_once_and_waits_for_a_running_scan() {
        let root = std::env::temp_dir().join(format!("thenex-sched-run-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let decoy = watch.join("payroll.docm");
        fs::write(&decoy, b"harmless decoy").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.watch_dir = Some(watch);
        cfg.ensure_dirs().unwrap();
        let list = root.join("list.bin");
        let digest = known_bad::hash_file(&decoy, u64::MAX).unwrap();
        known_bad::write_list(&list, &[digest], 1_795_000_000).unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        // Live protection is on and nothing is in dry run: a quick scan would move the decoy.
        assert!(!cfg.is_dry_run() && cfg.engine_enabled(Engine::KnownBad));
        let mut toggles = cfg.toggles.snapshot();
        toggles.scan_schedule = ScanSchedule::Daily;
        cfg.toggles.apply(toggles);

        let (cfg, jobs) = (Arc::new(cfg), Arc::new(ScanJobs::default()));
        let scanner = Arc::new(BinaryAiScanner::heuristic_only());
        let telemetry = Arc::new(Telemetry::default());
        let mut scheduler = Scheduler::load(&cfg);
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(!jobs.is_running(), "the quiet period has not passed");
        scheduler.quiet = Duration::ZERO;

        // A user scan is running: nothing starts, and the run is not recorded, so it is retried.
        assert!(jobs.start(ScanKind::Full, &cfg, &scanner, &telemetry));
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert_eq!(read_state(&cfg).last_run, None);
        for _ in 0..400 {
            if !jobs.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(!jobs.is_running());

        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(read_state(&cfg).last_run.is_some(), "recorded when started");
        for _ in 0..400 {
            if !jobs.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let report = crate::engine::read_scan_report(&cfg, ScanKind::Scheduled).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert!(report.dry_run && !report.full && !report.finished_at.is_empty());
        assert!(decoy.exists(), "a scheduled scan never moves a file");
        assert!(
            !cfg.quarantine_dir.exists() || fs::read_dir(&cfg.quarantine_dir).unwrap().count() == 0
        );
        let events = crate::quarantine::read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        let summaries: Vec<_> = events
            .iter()
            .filter(|e| e.threat_type == crate::engine::SCHEDULED_SCAN_EVENT)
            .collect();
        assert_eq!(summaries.len(), 1, "one summary, not one alert per finding");
        assert!(summaries[0].details.starts_with("scheduled, report only;"));
        assert!(events
            .iter()
            .any(|e| e.threat_type == known_bad::THREAT_TYPE && e.quiet));

        // Not due again for a day, and a restart reads the same record.
        let finished = report.finished_at;
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        let mut restarted = Scheduler::load(&cfg);
        restarted.quiet = Duration::ZERO;
        restarted.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(!jobs.is_running());
        assert_eq!(
            crate::engine::read_scan_report(&cfg, ScanKind::Scheduled)
                .unwrap()
                .finished_at,
            finished
        );

        // Dry run and the engine switch are still respected: switched off, nothing is flagged.
        let mut toggles = cfg.toggles.snapshot();
        toggles.set(Engine::KnownBad, false);
        cfg.toggles.apply(toggles);
        assert!(jobs.start(ScanKind::Scheduled, &cfg, &scanner, &telemetry));
        for _ in 0..400 {
            if !jobs.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(crate::engine::read_scan_report(&cfg, ScanKind::Scheduled)
            .unwrap()
            .findings
            .is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
