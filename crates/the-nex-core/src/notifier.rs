use crate::config::AppConfig;
use crate::platform;
use crate::quarantine::{self, ThreatEvent};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_READ_PER_POLL: u64 = 1024 * 1024;
const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOASTS_PER_POLL: usize = 3;

/// Follows `events.jsonl` like `tail -F`: survives creation, truncation and rotation.
pub struct EventTail {
    path: PathBuf,
    offset: u64,
    created: Option<SystemTime>,
    pending: Vec<u8>,
}

impl EventTail {
    /// Starts at the current end so only events written from now on are reported.
    pub fn new(path: PathBuf) -> Self {
        let meta = fs::metadata(&path).ok();
        Self {
            offset: meta.as_ref().map(|m| m.len()).unwrap_or(0),
            created: meta.and_then(|m| m.created().ok()),
            pending: Vec::new(),
            path,
        }
    }

    pub fn from_start(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            created: None,
            pending: Vec::new(),
        }
    }

    fn reset(&mut self, created: Option<SystemTime>) {
        self.offset = 0;
        self.created = created;
        self.pending.clear();
    }

    pub fn poll(&mut self) -> Vec<ThreatEvent> {
        let meta = match fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(_) => {
                self.reset(None);
                return Vec::new();
            }
        };
        let created = meta.created().ok();
        let replaced = self.created.is_some() && created.is_some() && created != self.created;
        if replaced || meta.len() < self.offset {
            self.reset(created);
        }
        self.created = created;
        if meta.len() == self.offset {
            return Vec::new();
        }

        let mut chunk = Vec::new();
        let offset = self.offset;
        let read = File::open(&self.path).and_then(|mut file| {
            file.seek(SeekFrom::Start(offset))?;
            file.take(MAX_READ_PER_POLL).read_to_end(&mut chunk)
        });
        let Ok(read) = read else {
            return Vec::new();
        };
        self.offset += read as u64;
        self.pending.extend_from_slice(&chunk);

        let Some(last_newline) = self.pending.iter().rposition(|&b| b == b'\n') else {
            if self.pending.len() > MAX_PENDING_BYTES {
                self.pending.clear();
            }
            return Vec::new();
        };
        let complete: Vec<u8> = self.pending.drain(..=last_newline).collect();
        String::from_utf8_lossy(&complete)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_str::<ThreatEvent>(line).ok())
            .collect()
    }
}

fn deliver(events: &[ThreatEvent], events_path: &std::path::Path) {
    for event in events.iter().take(MAX_TOASTS_PER_POLL) {
        platform::send_desktop_notification(
            &quarantine::notification_title(event),
            &quarantine::notification_body(event),
        );
    }
    if events.len() > MAX_TOASTS_PER_POLL {
        platform::send_desktop_notification(
            "The Nex",
            &format!(
                "{} more threat events recorded. See {}",
                events.len() - MAX_TOASTS_PER_POLL,
                events_path.display()
            ),
        );
    }
}

pub fn run_notifier(cfg: &AppConfig, shutdown: Arc<AtomicBool>) {
    let mut tail = EventTail::new(cfg.events_log.clone());
    while !shutdown.load(Ordering::SeqCst) {
        let mut events = tail.poll();
        events.retain(|e| !e.quiet);
        // A tray icon in this session already toasts alerts; stay quiet to avoid duplicates.
        if !events.is_empty() && !platform::tray_is_running() {
            deliver(&events, &cfg.events_log);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::Severity;
    use std::io::Write;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-notifier-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = fs::remove_file(&path);
        path
    }

    fn append(path: &PathBuf, text: &str) {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn line(kind: &str) -> String {
        let event = ThreatEvent::new(kind, Severity::High, "target", "TERMINATED", "d");
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    #[test]
    fn tails_only_new_complete_lines() {
        let path = temp_file("tail.jsonl");
        append(&path, &line("OLD"));
        let mut tail = EventTail::new(path.clone());
        assert!(tail.poll().is_empty());

        let next = line("NEW");
        let (head, rest) = next.split_at(10);
        append(&path, head);
        assert!(tail.poll().is_empty());
        append(&path, rest);
        let events = tail.poll();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].threat_type, "NEW");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn restarts_after_truncation() {
        let path = temp_file("rotate.jsonl");
        append(&path, &line("A"));
        append(&path, &line("B"));
        let mut tail = EventTail::from_start(path.clone());
        assert_eq!(tail.poll().len(), 2);
        fs::write(&path, line("C")).unwrap();
        let events = tail.poll();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].threat_type, "C");
        let _ = fs::remove_file(&path);
    }
}
