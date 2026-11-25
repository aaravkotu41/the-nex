//! `--check-file`: the verdict for one file the user handed over, with every engine that can
//! judge it and no side effects. Nothing is moved, quarantined, recorded or sent; the file is
//! only read. It runs in a child process of the app (see the GUI's `filecheck`), because the file
//! is hostile input.

use crate::ai_policy;
use crate::bin_ai::BinaryAiScanner;
use crate::config::AppConfig;
use crate::engine::{self, FileKind};
use crate::known_bad::{self, MAX_HASH_BYTES};
use crate::quarantine::to_hex;
use crate::zip_bomb::{self, ZipThreat, ZipThreatKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Larger files are refused: they would be hashed and parsed in full, and the list holds none.
pub const MAX_CHECK_BYTES: u64 = MAX_HASH_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Suspicious,
    NothingFound,
    /// No engine applies to this kind of file.
    NotScanned,
    /// Nothing was found, but a time or size limit stopped the check before it was finished.
    PartlyChecked,
    /// The file was not opened (folder, device, too big, unreadable).
    Refused,
}

/// The only thing a check reports about a file. Deliberately no path and no contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCheck {
    pub name: String,
    pub verdict: Verdict,
    /// Programs only: the AI score and the score at which The Nex acts.
    pub score: Option<f32>,
    pub threshold: Option<f32>,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    /// Plain-language sentences, strongest first.
    pub reasons: Vec<String>,
    /// Which checks actually ran: "program", "signature", "archive", "list".
    pub checks: Vec<String>,
}

/// Bidi controls and zero-width characters: invisible, but they change how text reads.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{061C}' | '\u{FEFF}')
}

/// A file name made safe to show: no bidi or zero-width characters (they can make `exe.txt`
/// read as `txt.exe`), control characters become spaces, at most 200 characters.
pub fn clean_display_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !is_invisible_format(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

pub fn display_name(path: &Path) -> String {
    clean_display_name(
        &path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy(),
    )
}

fn refused(name: String, size: Option<u64>, why: String) -> FileCheck {
    FileCheck {
        name,
        verdict: Verdict::Refused,
        score: None,
        threshold: None,
        size,
        sha256: None,
        reasons: vec![why],
        checks: Vec::new(),
    }
}

fn megabytes(bytes: u64) -> String {
    format!("{} MB", bytes.div_ceil(1024 * 1024))
}

fn zip_reason(threat: &ZipThreat) -> String {
    let what = match threat.kind {
        ZipThreatKind::CompressionRatio => "It unpacks to vastly more data than it holds, which is how a \"zip bomb\" fills a disk",
        ZipThreatKind::UncompressedSize => "It would unpack to an enormous size",
        ZipThreatKind::OverlappingEntries => "Its contents overlap each other, a trick used to hide a huge payload in a small file",
        ZipThreatKind::NestingDepth => "It has archives inside archives inside archives, a trick used to hide how big it really is",
        ZipThreatKind::NestedSizeMismatch => "An archive inside it claims a different size than it really has",
        ZipThreatKind::EntryCount => "It lists far more files than any real archive holds",
        ZipThreatKind::HeaderMismatch => "Its internal records disagree with each other, a trick used to fool scanners",
        ZipThreatKind::Malformed => "It is damaged or built wrongly on purpose, so it cannot be read safely",
    };
    format!(
        "{what} (about {} packed, {} unpacked).",
        megabytes(threat.total_compressed),
        megabytes(threat.total_uncompressed)
    )
}

/// The engine's wording for a program signal, said plainly.
fn plain_signal(signal: &str) -> String {
    let rewrite = [
        (
            "packed or encrypted code",
            "Its code looks scrambled or packed, which malware does to hide.",
        ),
        (
            "packer section names",
            "It is built from sections named like those packing tools make.",
        ),
        (
            "writable+executable",
            "Parts of it can be both changed and run, which malware uses to inject code.",
        ),
        (
            "entry point outside",
            "It starts running from an unusual place.",
        ),
        (
            "very few imports",
            "It uses almost none of the usual system functions, which is odd for a normal program.",
        ),
        (
            "risky APIs",
            "It can use system functions that malware often relies on.",
        ),
        (
            "large appended data",
            "It carries a large block of extra data tacked on at the end.",
        ),
        (
            "not digitally signed",
            "It is not digitally signed, so its maker cannot be confirmed.",
        ),
    ];
    rewrite
        .iter()
        .find(|(prefix, _)| signal.starts_with(prefix))
        .map(|(_, plain)| (*plain).to_string())
        .unwrap_or_else(|| format!("{signal}."))
}

/// Looks at one file and says what The Nex's engines make of it. Read-only: `cfg` must have had
/// its known-malware list loaded, and its toggles are ignored (a check is asked for by the user).
pub fn check(cfg: &AppConfig, scanner: &BinaryAiScanner, path: &Path) -> FileCheck {
    let name = display_name(path);
    // Resolve a link first so a shortcut to a document works and one to a device does not.
    let Ok(target) = fs::canonicalize(path) else {
        return refused(name, None, "That file could not be found.".into());
    };
    let Ok(meta) = fs::symlink_metadata(&target) else {
        return refused(name, None, "That file could not be read.".into());
    };
    if meta.is_dir() {
        return refused(
            name,
            None,
            "That is a folder. Drop the files inside it instead.".into(),
        );
    }
    if !meta.is_file() {
        return refused(
            name,
            None,
            "That is a device or special system file, not a document or program, so it was not opened."
                .into(),
        );
    }
    let size = meta.len();
    if size > MAX_CHECK_BYTES {
        return refused(
            name,
            Some(size),
            format!(
                "That file is too big to check here (the limit is {}).",
                megabytes(MAX_CHECK_BYTES)
            ),
        );
    }
    let Some(digest) = known_bad::hash_file(&target, MAX_CHECK_BYTES) else {
        return refused(
            name,
            Some(size),
            "That file could not be read. You may not have permission to open it.".into(),
        );
    };

    let mut checks = Vec::new();
    let mut reasons = Vec::new();
    let mut suspicious = false;
    // True once something other than the list looked at the file's contents.
    let mut examined = false;
    let mut partial = false;
    let (mut score, mut threshold) = (None, None);
    let kind = engine::classify_file(&target);
    let listed = !cfg.known_bad.is_empty();

    if listed {
        checks.push("list".to_string());
        if cfg.known_bad.contains(&digest) {
            suspicious = true;
            reasons.push(format!(
                "It matches a file on the known-malware list ({}).",
                cfg.known_bad.summary()
            ));
        }
    }
    match kind {
        FileKind::Archive => {
            checks.push("archive".to_string());
            examined = true;
            let (threat, incomplete) = zip_bomb::inspect_zip_file_checked(&target, cfg);
            if let Some(threat) = threat {
                suspicious = true;
                reasons.push(zip_reason(&threat));
            } else if incomplete {
                partial = true;
                reasons.push(
                    "It is too large or complicated to check completely, so the check stopped early and part of it was not examined."
                        .into(),
                );
            }
            reasons.push(
                "Only the archive's structure was checked. The files inside it were not checked for malware."
                    .into(),
            );
        }
        FileKind::Binary if scanner.is_trusted(&target) => {
            checks.push("signature".to_string());
            examined = true;
            reasons.push(
                "It was trusted because it carries a signature from a publisher this computer trusts. It was not scored, and only its signature was checked."
                    .into(),
            );
        }
        FileKind::Binary => match scanner.assess(&target) {
            Some(assessment) => {
                checks.push("program".to_string());
                examined = true;
                let limit = ai_policy::effective_threshold(cfg.ai_threshold);
                score = Some(assessment.score);
                threshold = Some(limit);
                if assessment.score >= limit {
                    suspicious = true;
                    reasons.extend(assessment.reasons.iter().map(|r| plain_signal(r)));
                }
            }
            None => reasons.push(
                "It looks like a program, but it could not be read as one (it may be damaged or very large), so it was not scored."
                    .into(),
            ),
        },
        FileKind::Other => reasons.push(
            "This is not a program or archive, so there is nothing to score.".to_string(),
        ),
    }
    if !examined && !suspicious {
        reasons.push(if listed {
            "It is not on the known-malware list. Nothing else could be checked for it.".to_string()
        } else {
            "No known-malware list is installed, so nothing could be checked.".to_string()
        });
    }
    if cfg.is_allowed(&digest) {
        reasons.push(
            "This exact file is on your always-allow list. That does not change this result."
                .into(),
        );
    }
    let verdict = if suspicious {
        Verdict::Suspicious
    } else if !examined {
        Verdict::NotScanned
    } else if partial {
        Verdict::PartlyChecked
    } else {
        Verdict::NothingFound
    };
    FileCheck {
        name,
        verdict,
        score,
        threshold,
        size: Some(size),
        sha256: Some(to_hex(&digest)),
        reasons,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("thenex-check-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn zip_of(data: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("a.bin", options).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap();
        cursor.into_inner()
    }

    fn run(dir: &Path, file: &Path) -> FileCheck {
        let cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
        check(&cfg, &BinaryAiScanner::heuristic_only(), file)
    }

    /// Every file under `dir` with its size and modified time.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, std::time::SystemTime)> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            for entry in fs::read_dir(&next).unwrap().flatten() {
                let meta = entry.metadata().unwrap();
                out.insert(entry.path(), (meta.len(), meta.modified().unwrap()));
                if meta.is_dir() {
                    stack.push(entry.path());
                }
            }
        }
        out
    }

    #[test]
    fn refuses_folders_missing_files_and_devices_without_opening_them() {
        let dir = scratch("refuse");
        let folder = dir.join("stuff");
        fs::create_dir(&folder).unwrap();
        let result = run(&dir, &folder);
        assert_eq!(result.verdict, Verdict::Refused);
        assert!(result.reasons[0].contains("folder"));
        assert_eq!(run(&dir, &dir.join("gone.exe")).verdict, Verdict::Refused);

        #[cfg(unix)]
        {
            let fifo = dir.join("pipe");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            let link = dir.join("link-to-pipe");
            std::os::unix::fs::symlink(&fifo, &link).unwrap();
            for target in [&fifo, &link] {
                let result = run(&dir, target); // would hang here if the pipe were opened
                assert_eq!(result.verdict, Verdict::Refused);
                assert!(result.reasons[0].contains("device or special"));
            }
            let device = run(&dir, Path::new("/dev/null"));
            assert_eq!(device.verdict, Verdict::Refused);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_file_over_the_size_limit() {
        let dir = scratch("big");
        let big = dir.join("huge.iso");
        fs::File::create(&big)
            .unwrap()
            .set_len(MAX_CHECK_BYTES + 1)
            .unwrap();
        let result = run(&dir, &big);
        assert_eq!(result.verdict, Verdict::Refused);
        assert_eq!(result.size, Some(MAX_CHECK_BYTES + 1));
        assert!(result.reasons[0].contains("too big"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn other_files_say_there_is_nothing_to_score_and_the_json_has_no_path() {
        let dir = scratch("other");
        let note = dir.join("note.txt");
        fs::write(&note, b"hello").unwrap();
        let result = run(&dir, &note);
        assert_eq!(result.verdict, Verdict::NotScanned);
        assert!(result.reasons[0].contains("not a program or archive"));
        assert_eq!(result.sha256.as_deref().map(str::len), Some(64));
        let json = serde_json::to_value(&result).unwrap();
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
                "checks",
                "name",
                "reasons",
                "score",
                "sha256",
                "size",
                "threshold",
                "verdict"
            ]
        );
        assert_eq!(json["verdict"], "not_scanned");
        assert!(!json.to_string().contains(dir.to_str().unwrap()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoys_are_reported_and_nothing_anywhere_changes() {
        let dir = scratch("decoys");
        let bomb = dir.join("watched").join("bomb.zip");
        let listed = dir.join("watched").join("listed.bin");
        let fine = dir.join("watched").join("fine.zip");
        fs::create_dir_all(bomb.parent().unwrap()).unwrap();
        fs::write(&bomb, zip_of(&vec![0u8; 80 * 1024 * 1024])).unwrap();
        fs::write(&listed, b"harmless decoy that is on the list").unwrap();
        fs::write(&fine, zip_of(b"a short harmless note\n")).unwrap();
        let list = dir.join("list.bin");
        let digest = known_bad::hash_file(&listed, MAX_CHECK_BYTES).unwrap();
        known_bad::write_list(&list, &[digest], 1).unwrap();

        let mut cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
        cfg.ensure_dirs().unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        let scanner = BinaryAiScanner::heuristic_only();
        let before = snapshot(&dir);
        let bytes = fs::read(&bomb).unwrap();

        let bomb_result = check(&cfg, &scanner, &bomb);
        assert_eq!(bomb_result.verdict, Verdict::Suspicious);
        assert!(bomb_result.checks.contains(&"archive".to_string()));
        let listed_result = check(&cfg, &scanner, &listed);
        assert_eq!(listed_result.verdict, Verdict::Suspicious);
        assert!(listed_result.reasons[0].contains("known-malware list"));
        let fine_result = check(&cfg, &scanner, &fine);
        assert_eq!(fine_result.verdict, Verdict::NothingFound);
        assert_eq!(fine_result.checks, ["list", "archive"]);

        assert_eq!(snapshot(&dir), before, "a check must not touch any file");
        assert_eq!(fs::read(&bomb).unwrap(), bytes);
        assert_eq!(fs::metadata(&cfg.events_log).unwrap().len(), 0, "no event");
        assert_eq!(fs::read_dir(&cfg.quarantine_dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A config with a one-entry known-malware list that holds something else.
    fn listed_cfg(dir: &Path) -> AppConfig {
        let other = dir.join("other-listed.bin");
        fs::write(&other, b"some other listed file").unwrap();
        let list = dir.join("list.bin");
        let digest = known_bad::hash_file(&other, MAX_CHECK_BYTES).unwrap();
        known_bad::write_list(&list, &[digest], 1).unwrap();
        let mut cfg = AppConfig::for_base_dir(&dir.join("TheNex"));
        cfg.ensure_dirs().unwrap();
        cfg.hash_list = Some(list);
        cfg.load_known_bad().unwrap();
        cfg
    }

    #[test]
    fn an_archive_says_its_contents_were_not_checked() {
        let dir = scratch("archive-words");
        let fine = dir.join("fine.zip");
        fs::write(&fine, zip_of(b"a short harmless note\n")).unwrap();
        let result = run(&dir, &fine);
        assert_eq!(result.verdict, Verdict::NothingFound);
        assert!(
            result
                .reasons
                .iter()
                .any(|r| r.contains("inside it were not checked for malware")),
            "{:?}",
            result.reasons
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_check_cut_short_by_a_budget_is_not_reported_as_nothing_found() {
        let dir = scratch("partial");
        // 70 MB of noise: it cannot be a ratio bomb, but it is more than the 64 MB the archive
        // check is willing to decompress.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let noise: Vec<u8> = (0..70 * 1024 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        let mut cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(1));
        writer.start_file("big.bin", options).unwrap();
        writer.write_all(&noise).unwrap();
        writer.finish().unwrap();
        let file = dir.join("big.zip");
        fs::write(&file, cursor.into_inner()).unwrap();
        let result = run(&dir, &file);
        assert_eq!(result.verdict, Verdict::PartlyChecked, "{result:?}");
        assert!(result.reasons.iter().any(|r| r.contains("stopped early")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_a_list_loaded_a_file_nothing_could_score_is_not_green() {
        let dir = scratch("list-only");
        let cfg = listed_cfg(&dir);
        let scanner = BinaryAiScanner::heuristic_only();
        let note = dir.join("note.txt");
        fs::write(&note, b"hello").unwrap();
        let broken = dir.join("broken.exe");
        fs::write(&broken, b"MZ not really a program").unwrap();
        for file in [&note, &broken] {
            let result = check(&cfg, &scanner, file);
            assert_eq!(result.verdict, Verdict::NotScanned, "{file:?}: {result:?}");
            assert_eq!(result.checks, ["list"]);
            assert!(
                result
                    .reasons
                    .iter()
                    .any(|r| r.contains("not on the known-malware list")),
                "{:?}",
                result.reasons
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_signed_program_shows_a_signature_check_not_a_score() {
        let dir = scratch("signed");
        let result = run(&dir, Path::new("/bin/ls"));
        assert_eq!(result.verdict, Verdict::NothingFound, "{result:?}");
        assert_eq!(result.checks, ["signature"]);
        assert!(result.score.is_none());
        assert!(result.reasons[0].contains("because it carries a signature"));
        assert!(result.reasons[0].contains("not scored"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_always_allowed_file_says_so_and_keeps_its_verdict() {
        let dir = scratch("allowed");
        let cfg = listed_cfg(&dir);
        let scanner = BinaryAiScanner::heuristic_only();
        let note = dir.join("note.txt");
        fs::write(&note, b"hello").unwrap();
        let before = check(&cfg, &scanner, &note);
        assert!(!before.reasons.iter().any(|r| r.contains("always-allow")));
        let sha = before.sha256.clone().unwrap();
        let entry = crate::allowlist::AllowedFile::new(&sha, "note.txt", "ZIP_BOMB").unwrap();
        crate::allowlist::add(&cfg, entry).unwrap();
        let after = check(&cfg, &scanner, &note);
        assert_eq!(after.verdict, before.verdict);
        assert!(after.reasons.iter().any(|r| r.contains("always-allow")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_shown_to_people_lose_bidi_and_zero_width_characters() {
        let tricky = "invoice\u{202E}gpj.exe\u{200B}\u{FEFF}\u{2066}x\u{061C}\n.zip";
        assert_eq!(clean_display_name(tricky), "invoicegpj.exex .zip");
        assert_eq!(display_name(Path::new("/a/b\u{202E}c.txt")), "bc.txt");
    }
}
