//! Scheduled scans: the setting, when a scan is due, and the record of the last one.
//!
//! The service checks once a second (`Scheduler::tick`). A scheduled scan never acts on what it
//! finds (see `ScanKind::Scheduled`), and only the local `--set scan_schedule=...` path or the
//! app's own settings command changes the setting: nothing a remote command can reach.
//!
//! A run counts (`last_run`) only when the scan finished. Every start is also written down first
//! (`last_attempt`), so a scan that crashes the service cannot start again at once.
//! shortcut: no battery check. Nothing in this tree reads the power source, so a scheduled scan
//! can run on a laptop that is unplugged and low; the Settings text says so. Skip it below ~20%
//! unplugged once a platform call for that exists.

use crate::bin_ai::BinaryAiScanner;
use crate::config::{write_atomic, AppConfig};
use crate::engine::ScanKind;
use crate::logger;
use crate::scan_jobs::ScanJobs;
use crate::status::Telemetry;
use chrono::{DateTime, Duration as Span, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const STATE_FILE: &str = "scheduled_scan.json";
/// Wait after the service starts, the schedule is switched on, or the machine wakes (or the
/// clock jumps forward), before a scan: one the moment the Mac wakes would be a surprise.
const QUIET: Duration = Duration::from_secs(10 * 60);
/// Least time between two starts, finished or not: a crash loop cannot rescan back to back.
const RETRY_GAP: Span = Span::hours(1);
/// Ticks come about a second apart; a longer gap (or a clock far ahead of the monotonic one)
/// means the machine slept or the clock was set forward.
const WAKE_GAP: Duration = Duration::from_secs(30);
/// Findings an earlier scheduled scan already reported, kept between runs.
pub const SEEN_FILE: &str = "scheduled_seen.json";
const MAX_SEEN: usize = 5000;

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
    /// A scan finished (not stopped by a shutdown or a user's scan) at this time.
    pub last_run: Option<DateTime<Utc>>,
    /// A scan was started at this time, finished or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt: Option<DateTime<Utc>>,
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
    /// A recorded time is in the future (clock set back, or a damaged file): pull it back to
    /// `now`, or no scan would run until the clock caught up.
    ResetClock,
}

/// `settled`: the quiet period since start (or since the schedule was switched on, or the last
/// wake) is over. A scan runs once when `interval` has passed since the last finished one,
/// however long ago that was (one catch-up, never one per missed day), and at least
/// `RETRY_GAP` after the last start; the caller records the start, which ends the loop.
pub fn verdict(
    schedule: ScanSchedule,
    now: DateTime<Utc>,
    last_run: Option<DateTime<Utc>>,
    last_attempt: Option<DateTime<Utc>>,
    settled: bool,
) -> Verdict {
    let Some(interval) = schedule.interval() else {
        return Verdict::Wait;
    };
    if last_run.is_some_and(|t| t > now) || last_attempt.is_some_and(|t| t > now) {
        return Verdict::ResetClock;
    }
    if !settled || last_attempt.is_some_and(|t| now - t < RETRY_GAP) {
        return Verdict::Wait;
    }
    match last_run {
        Some(last) if now - last < interval => Verdict::Wait,
        _ => Verdict::Run,
    }
}

/// True when the time between two ticks shows a sleep or a clock set forward: the wall clock
/// moved on much more than the monotonic one (which stops while asleep on macOS and Linux), or
/// the monotonic gap alone is far longer than a tick (it keeps running on Windows).
pub fn woke(monotonic: Duration, wall: Span) -> bool {
    let mono = Span::from_std(monotonic).unwrap_or(Span::MAX);
    let limit = Span::from_std(WAKE_GAP).unwrap_or(Span::MAX);
    monotonic > WAKE_GAP || wall - mono > limit
}

/// Findings that scheduled scans already reported. A finding is the same again when its file
/// hash (or, with none, its path, size and modified time) is the same, so the daily scan of a
/// file nobody dealt with does not add a new threat event every day.
#[derive(Debug, Default)]
pub struct SeenFindings {
    before: HashSet<String>,
    now: Mutex<HashSet<String>>,
}

impl SeenFindings {
    pub fn load(path: &Path) -> Self {
        let before = fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            .unwrap_or_default();
        Self {
            before: before.into_iter().collect(),
            now: Mutex::default(),
        }
    }

    /// The path is always part of the key (a second copy elsewhere is a new finding). Without a
    /// hash the file's size and both of its times and the event's text stand in for it.
    fn key(event: &crate::quarantine::ThreatEvent) -> Option<String> {
        if let Some(hash) = &event.sha256 {
            return Some(format!("{}|{}|{hash}", event.threat_type, event.target));
        }
        let meta = fs::symlink_metadata(&event.target).ok()?;
        let nanos = |t: std::time::SystemTime| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_nanos())
        };
        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt;
            (meta.ctime() as i128) * 1_000_000_000 + meta.ctime_nsec() as i128
        };
        #[cfg(not(unix))]
        let changed = meta.created().ok().and_then(nanos).unwrap_or(0) as i128;
        Some(format!(
            "{}|{}|{}|{}|{changed}|{}",
            event.threat_type,
            event.target,
            meta.len(),
            nanos(meta.modified().ok()?)?,
            event.details
        ))
    }

    /// True when an earlier scan already reported this finding unchanged. Notes it as seen now.
    pub fn is_repeat(&self, event: &crate::quarantine::ThreatEvent) -> bool {
        let Some(key) = Self::key(event) else {
            return false;
        };
        let repeat = self.before.contains(&key);
        self.now
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key);
        repeat
    }

    /// Keeps what this scan saw. A scan that stopped early adds to the old list instead of
    /// replacing it, since it did not look at everything.
    pub fn save(&self, path: &Path, complete: bool) {
        let mut keep = self.now.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if !complete {
            keep.extend(self.before.iter().cloned());
        }
        let mut keep: Vec<_> = keep.into_iter().collect();
        keep.truncate(MAX_SEEN);
        if let Ok(json) = serde_json::to_vec(&keep) {
            if let Err(e) = write_atomic(path, &json) {
                logger::warn(format!("cannot record reported findings: {e}"));
            }
        }
    }
}

pub struct Scheduler {
    state: ScheduleState,
    quiet: Duration,
    /// When the quiet period began (the schedule first seen on, or the last wake); None while off.
    armed: Option<Instant>,
    last_tick: Option<(Instant, DateTime<Utc>)>,
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
            last_tick: None,
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
        let (mono, now) = (Instant::now(), Utc::now());
        // Only a scan that ran to the end counts; one stopped by a shutdown or by the user's
        // own scan is tried again once `RETRY_GAP` has passed.
        if jobs.take_scheduled_outcome() == Some(true) {
            self.state.last_run = Some(now);
            self.save(cfg);
        }
        if let Some((m, w)) = self.last_tick.replace((mono, now)) {
            if woke(mono.duration_since(m), now - w) {
                self.armed = None;
            }
        }
        if cfg.toggles.scan_schedule() == ScanSchedule::Off {
            self.armed = None;
            return;
        }
        let armed = *self.armed.get_or_insert(mono);
        let settled = armed.elapsed() >= self.quiet;
        match verdict(
            cfg.toggles.scan_schedule(),
            now,
            self.state.last_run,
            self.state.last_attempt,
            settled,
        ) {
            Verdict::Wait => {}
            Verdict::ResetClock => {
                for t in [&mut self.state.last_run, &mut self.state.last_attempt] {
                    if t.is_some_and(|t| t > now) {
                        *t = Some(now);
                    }
                }
                self.save(cfg);
            }
            Verdict::Run if jobs.is_running() => {}
            Verdict::Run => {
                // Written before the scan starts, so a crash in it is not retried at once.
                self.state.last_attempt = Some(now);
                self.save(cfg);
                jobs.start(ScanKind::Scheduled, cfg, scanner, telemetry);
            }
        }
    }

    /// Kept in memory too, so a data folder that cannot be written still runs once, not forever.
    fn save(&mut self, cfg: &AppConfig) {
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
        assert_eq!(
            verdict(ScanSchedule::Off, at(0), None, None, true),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), None, None, false),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), None, None, true),
            Verdict::Run
        );
    }

    #[test]
    fn a_scan_is_due_exactly_one_interval_after_the_last() {
        let last = Some(at(0));
        for (schedule, interval) in [(ScanSchedule::Daily, DAY), (ScanSchedule::Weekly, 7 * DAY)] {
            assert_eq!(
                verdict(schedule, at(interval - 1), last, None, true),
                Verdict::Wait
            );
            assert_eq!(
                verdict(schedule, at(interval), last, None, true),
                Verdict::Run
            );
            assert_eq!(
                verdict(schedule, at(interval + 1), last, None, true),
                Verdict::Run
            );
        }
        // Switched from daily to weekly: the last run counts against the longer interval.
        assert_eq!(
            verdict(ScanSchedule::Weekly, at(3 * DAY), last, None, true),
            Verdict::Wait
        );
    }

    #[test]
    fn a_long_absence_gives_one_catch_up_run_not_one_per_missed_day() {
        let mut last = Some(at(0));
        let now = at(90 * DAY);
        assert_eq!(
            verdict(ScanSchedule::Daily, now, last, None, true),
            Verdict::Run
        );
        last = Some(now); // what the scheduler records when it starts the scan
        assert_eq!(
            verdict(ScanSchedule::Daily, now, last, None, true),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(91 * DAY - 1), last, None, true),
            Verdict::Wait
        );
    }

    #[test]
    fn a_clock_set_back_resets_instead_of_waiting_for_the_future_or_looping() {
        // Last run recorded "tomorrow" (clock set back, or a damaged file): reset at once, even
        // inside the quiet period, then the normal interval applies from now.
        for settled in [false, true] {
            assert_eq!(
                verdict(ScanSchedule::Daily, at(0), Some(at(DAY)), None, settled),
                Verdict::ResetClock
            );
        }
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), Some(at(0)), None, true),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Off, at(0), Some(at(DAY)), None, true),
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
        scheduler.state.last_run = Some(at(5));
        scheduler.save(&cfg);
        assert_eq!(read_state(&cfg).last_run, Some(at(5)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_start_is_not_repeated_within_the_retry_gap_and_a_future_attempt_resets() {
        // A crash loop: the scan never finishes (no last_run), but it was started a minute ago.
        let old = Some(at(-30 * DAY));
        assert_eq!(
            verdict(ScanSchedule::Daily, at(60), old, Some(at(0)), true),
            Verdict::Wait
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(3600), old, Some(at(0)), true),
            Verdict::Run
        );
        assert_eq!(
            verdict(ScanSchedule::Daily, at(0), old, Some(at(5)), true),
            Verdict::ResetClock
        );
    }

    #[test]
    fn sleep_or_a_clock_jump_forward_is_seen_between_ticks() {
        let s = Span::seconds;
        assert!(!woke(Duration::from_secs(1), s(1)));
        assert!(!woke(Duration::from_secs(1), s(-3600))); // clock set back: ResetClock's job
        assert!(woke(Duration::from_secs(1), s(8 * 3600))); // asleep (monotonic stood still)
        assert!(woke(Duration::from_secs(8 * 3600), s(8 * 3600))); // monotonic ran on (Windows)
        assert!(woke(Duration::from_secs(1), s(120))); // clock set forward
    }

    #[test]
    fn only_a_finished_scan_counts_and_a_stopped_one_is_retried_after_the_gap() {
        let root = std::env::temp_dir().join(format!("thenex-sched-out-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let cfg = AppConfig::for_base_dir(&root);
        cfg.ensure_dirs().unwrap();
        let mut toggles = cfg.toggles.snapshot();
        toggles.scan_schedule = ScanSchedule::Daily;
        cfg.toggles.apply(toggles);
        let (cfg, jobs) = (Arc::new(cfg), Arc::new(ScanJobs::default()));
        let scanner = Arc::new(BinaryAiScanner::heuristic_only());
        let telemetry = Arc::new(Telemetry::default());
        let mut scheduler = Scheduler::load(&cfg);
        // Stopped (shutdown, or a user's scan took over): not recorded as a run.
        jobs.set_scheduled_outcome(false);
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert_eq!(read_state(&cfg).last_run, None);
        jobs.set_scheduled_outcome(true);
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(read_state(&cfg).last_run.is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_finding_reported_before_and_unchanged_is_not_logged_as_a_new_threat() {
        let root = std::env::temp_dir().join(format!("thenex-sched-seen-{}", std::process::id()));
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
        let scanner = BinaryAiScanner::heuristic_only();
        let telemetry = Telemetry::default();
        let run = |cfg: &AppConfig| {
            let report = crate::engine::run_scan(
                cfg,
                &scanner,
                &telemetry,
                ScanKind::Scheduled,
                &mut |_, _| true,
            );
            let events = crate::quarantine::read_recent_events(&cfg.events_log, 1 << 20).unwrap();
            let threats = events
                .iter()
                .filter(|e| e.threat_type == known_bad::THREAT_TYPE)
                .count();
            (report.findings.len(), threats)
        };
        assert_eq!(run(&cfg), (1, 1));
        assert_eq!(run(&cfg), (1, 1), "the report still lists it, no new event");
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&decoy, b"harmless decoy").unwrap(); // same bytes, new modified time
        assert_eq!(run(&cfg), (1, 2), "changed on disk: reported again");
        let _ = fs::remove_dir_all(&root);
    }

    fn finding(target: &Path, hash: Option<&str>, details: &str) -> crate::quarantine::ThreatEvent {
        let mut event = crate::quarantine::ThreatEvent::new(
            "MALWARE_AI",
            crate::quarantine::Severity::High,
            target.display().to_string(),
            "DRY_RUN",
            details,
        );
        event.sha256 = hash.map(str::to_string);
        event
    }

    #[test]
    fn a_finding_is_the_same_only_in_the_same_place_and_state() {
        let dir = std::env::temp_dir().join(format!("thenex-seen-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.bin"), dir.join("b.bin"));
        fs::write(&a, b"same bytes").unwrap();
        fs::write(&b, b"same bytes").unwrap();
        let list = dir.join("seen.json");
        let first = SeenFindings::default();
        assert!(!first.is_repeat(&finding(&a, Some("h1"), "d")));
        assert!(!first.is_repeat(&finding(&a, None, "d")));
        first.save(&list, true);
        let seen = SeenFindings::load(&list);
        assert!(seen.is_repeat(&finding(&a, Some("h1"), "d")));
        assert!(seen.is_repeat(&finding(&a, None, "d")));
        // The same hash in another place, or another hash in the same place, is a new finding.
        assert!(!seen.is_repeat(&finding(&b, Some("h1"), "d")));
        assert!(!seen.is_repeat(&finding(&a, Some("h2"), "d")));
        // Without a hash the event's own text counts, and so does the file's change time.
        assert!(!seen.is_repeat(&finding(&a, None, "another verdict")));
        assert!(!seen.is_repeat(&finding(&b, None, "d")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::thread::sleep(Duration::from_millis(20));
            // Changes the change time only: same size, same modified time.
            fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(!SeenFindings::load(&list).is_repeat(&finding(&a, None, "d")));
        }
        // A file that is gone cannot be told apart: reported, never hidden.
        assert!(!seen.is_repeat(&finding(&dir.join("gone"), None, "d")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_scheduled_scan_hides_repeats_and_a_stopped_one_keeps_the_old_list() {
        let root = std::env::temp_dir().join(format!("thenex-sched-keep-{}", std::process::id()));
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
        let (scanner, telemetry) = (BinaryAiScanner::heuristic_only(), Telemetry::default());
        let threats = |cfg: &AppConfig| {
            crate::quarantine::read_recent_events(&cfg.events_log, 1 << 20)
                .unwrap()
                .iter()
                .filter(|e| e.threat_type == known_bad::THREAT_TYPE)
                .count()
        };
        let run = |kind: ScanKind, go_on: bool| {
            crate::engine::run_scan(&cfg, &scanner, &telemetry, kind, &mut |_, _| go_on)
        };
        let seen_file = cfg.base_dir.join(SEEN_FILE);
        let read_seen =
            || serde_json::from_slice::<Vec<String>>(&fs::read(&seen_file).unwrap()).unwrap();
        run(ScanKind::Scheduled, true);
        run(ScanKind::Scheduled, true);
        assert_eq!(threats(&cfg), 1, "the second scheduled scan adds no event");
        let before = read_seen();
        assert_eq!(before.len(), 1);
        // A scan the user asks for always reports what it finds.
        run(ScanKind::Full, true);
        assert_eq!(threats(&cfg), 2);
        run(ScanKind::Quick, true);
        assert_eq!(threats(&cfg), 3);
        // A scheduled scan that was stopped before it looked at anything forgets nothing.
        assert!(run(ScanKind::Scheduled, false).cancelled);
        assert_eq!(read_seen(), before);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn waking_from_sleep_restarts_the_quiet_period_before_a_scan() {
        let root = std::env::temp_dir().join(format!("thenex-sched-wake-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.watch_dir = Some(watch);
        cfg.ensure_dirs().unwrap();
        let mut toggles = cfg.toggles.snapshot();
        toggles.scan_schedule = ScanSchedule::Daily;
        cfg.toggles.apply(toggles);
        let (cfg, jobs) = (Arc::new(cfg), Arc::new(ScanJobs::default()));
        let scanner = Arc::new(BinaryAiScanner::heuristic_only());
        let telemetry = Arc::new(Telemetry::default());
        let ready = |gap: Span| {
            let mut scheduler = Scheduler::load(&cfg);
            // The quiet period ended long ago; the last tick was a second ago by the monotonic
            // clock and `gap` ago by the wall clock.
            scheduler.armed = Instant::now().checked_sub(Duration::from_secs(3600));
            let second = Duration::from_secs(1);
            scheduler.last_tick = Some((Instant::now() - second, Utc::now() - gap));
            scheduler
        };
        // The machine slept eight hours: wait the quiet period again, start nothing.
        let mut scheduler = ready(Span::hours(8));
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(!jobs.is_running() && read_state(&cfg).last_attempt.is_none());
        // The same state with an ordinary tick gap starts the scan.
        let mut scheduler = ready(Span::seconds(1));
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        assert!(read_state(&cfg).last_attempt.is_some());
        jobs.join();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_scheduled_scan_with_nothing_found_is_recorded_quietly_and_names_no_folder() {
        let root = std::env::temp_dir().join(format!("thenex-sched-quiet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let watch = root.join("watch");
        fs::create_dir_all(&watch).unwrap();
        fs::write(watch.join("notes.txt"), b"plain").unwrap();
        let mut cfg = AppConfig::for_base_dir(&root.join("base"));
        cfg.watch_dir = Some(watch);
        cfg.ensure_dirs().unwrap();
        let scanner = BinaryAiScanner::heuristic_only();
        crate::engine::run_scan(
            &cfg,
            &scanner,
            &Telemetry::default(),
            ScanKind::Scheduled,
            &mut |_, _| true,
        );
        let events = crate::quarantine::read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        let summary = events
            .iter()
            .find(|e| e.threat_type == crate::engine::SCHEDULED_SCAN_EVENT)
            .unwrap();
        assert!(summary.quiet && !summary.target.contains("watch"));
        // A user's own scan still alerts as before.
        crate::engine::run_scan(
            &cfg,
            &scanner,
            &Telemetry::default(),
            ScanKind::Full,
            &mut |_, _| true,
        );
        let events = crate::quarantine::read_recent_events(&cfg.events_log, 1 << 20).unwrap();
        assert!(
            !events
                .iter()
                .find(|e| e.threat_type == "FULL_SCAN")
                .unwrap()
                .quiet
        );
        let _ = fs::remove_dir_all(&root);
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
        assert_eq!(read_state(&cfg).last_attempt, None);
        for _ in 0..400 {
            if !jobs.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(!jobs.is_running());

        scheduler.tick(&cfg, &jobs, &scanner, &telemetry);
        let state = read_state(&cfg);
        assert!(state.last_attempt.is_some() && state.last_run.is_none());
        for _ in 0..400 {
            if !jobs.is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        scheduler.tick(&cfg, &jobs, &scanner, &telemetry); // learns that it finished
        assert!(
            read_state(&cfg).last_run.is_some(),
            "recorded when finished"
        );
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
        // One notification for the findings, and it names no folder or file.
        assert!(!summaries[0].quiet && summaries[0].target == "Scheduled scan");
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
