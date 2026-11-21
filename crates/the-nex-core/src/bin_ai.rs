//! Binary AI: scores new executables (PE and Mach-O) with a small on-device model.
//!
//! The feature definition and the PE extractor below are mirrored line for line by
//! scripts/thenex_features.py, which builds the training data (Mach-O training profiles are
//! synthetic, so the Mach-O extractor exists only here). CI compares the two on real files
//! (scripts/check_feature_parity.py): a model fed different numbers in production than in
//! training silently stops working, so change both sides together.

use crate::config::{AppConfig, MAX_AI_SCAN_BYTES};
use crate::logger::{self, lock_or_recover};
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

pub const FEATURE_COUNT: usize = 14;
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "size_log10_kb",
    "max_section_entropy",
    "entry_section_entropy",
    "section_count",
    "wx_section_ratio",
    "entry_point_anomaly",
    "import_count_log",
    "suspicious_import_ratio",
    "has_signature",
    "overlay_ratio",
    "packer_section_names",
    "resource_ratio",
    "is_dotnet",
    "is_macho",
];
/// Prefix matches, so "ShellExecute" also catches ShellExecuteW / ShellExecuteExW.
pub const SUSPICIOUS_IMPORTS: [&str; 16] = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "URLDownloadToFile",
    "IsDebuggerPresent",
    "WinExec",
    "ShellExecute",
    "QueueUserAPC",
    "NtWriteVirtualMemory",
    "SetThreadContext",
    "GetAsyncKeyState",
    "MiniDumpWriteDump",
    "InternetOpenUrl",
    "CryptEncrypt",
];
pub const SUSPICIOUS_MACHO_SYMBOLS: [&str; 7] = [
    "dlopen", "ptrace", "NSTask", "system", "popen", "execve", "mprotect",
];
/// Section names left behind by common packers and protectors (compared lowercase).
pub const PACKER_SECTION_NAMES: [&str; 28] = [
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".mpress1", ".mpress2", ".petite",
    ".nsp0", ".nsp1", ".nsp2", ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2", ".enigma1",
    ".enigma2", ".packed", ".rlpack", "pec2", "pec2to", ".perplex", ".spack", ".svkp", ".yp",
    ".boom",
];
/// Imported by nearly every MSVC program's C runtime, so it is never shown as a reason.
const COMMON_CRT_IMPORT: &str = "IsDebuggerPresent";
const MAX_LOG10_SIZE_KB: f64 = 6.0;
const SECTION_COUNT_SCALE: f64 = 16.0;
const IMPORT_LOG_SCALE: f64 = 3.0;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MAX_CACHE_ENTRIES: usize = 4096;
/// Entropy (bits/byte) above which code is almost always packed or encrypted.
const PACKED_ENTROPY: f64 = 7.2;

pub type FeatureVector = [f32; FEATURE_COUNT];
/// Wraps the optimized tract `SimplePlan`; returns P(malicious) or None on inference failure.
type InferenceFn = Box<dyn Fn(&FeatureVector) -> Option<f32> + Send + Sync>;

/// Raw facts about one executable, before normalisation. `features()` turns them into the
/// model input; `reasons()` turns them into plain-English explanations for a detection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BinaryProfile {
    /// "pe" or "macho".
    pub format: &'static str,
    pub size_bytes: u64,
    /// Highest Shannon entropy of any section, 0..8 bits per byte.
    pub max_section_entropy: f64,
    /// Entropy of the section holding the entry point (Mach-O: __TEXT,__text).
    pub entry_section_entropy: f64,
    /// Sections (PE) or segments (Mach-O).
    pub section_count: usize,
    /// Sections/segments that are both writable and executable.
    pub wx_sections: usize,
    /// Entry point outside an executable section, or in the last section (PE only).
    pub entry_anomaly: bool,
    pub import_count: usize,
    /// Which entries of SUSPICIOUS_IMPORTS / SUSPICIOUS_MACHO_SYMBOLS are imported.
    pub suspicious_imports: Vec<String>,
    /// An Authenticode table (PE) or LC_CODE_SIGNATURE (Mach-O) is present. Validity is
    /// checked separately by `platform::is_trusted_binary`.
    pub signed: bool,
    /// Bytes appended after the last section, not counting the signature.
    pub overlay_bytes: u64,
    pub packer_sections: Vec<String>,
    pub resource_bytes: u64,
    /// Has a CLR header (.NET assemblies legitimately import a single function).
    pub dotnet: bool,
}

impl Default for BinaryProfile {
    fn default() -> Self {
        Self {
            format: "pe",
            size_bytes: 0,
            max_section_entropy: 0.0,
            entry_section_entropy: 0.0,
            section_count: 0,
            wx_sections: 0,
            entry_anomaly: false,
            import_count: 0,
            suspicious_imports: Vec::new(),
            signed: false,
            overlay_bytes: 0,
            packer_sections: Vec::new(),
            resource_bytes: 0,
            dotnet: false,
        }
    }
}

impl BinaryProfile {
    pub fn is_macho(&self) -> bool {
        self.format == "macho"
    }

    /// Normalised model input, every value in [0, 1]. Mirrors thenex_features.features().
    pub fn features(&self) -> FeatureVector {
        let size = self.size_bytes as f64;
        let size_kb = (size / 1024.0).max(1.0);
        let sections = self.section_count as f64;
        let risky_total = if self.is_macho() {
            SUSPICIOUS_MACHO_SYMBOLS.len()
        } else {
            SUSPICIOUS_IMPORTS.len()
        } as f64;
        let ratio = |part: f64, whole: f64| {
            if whole > 0.0 {
                (part / whole).clamp(0.0, 1.0)
            } else {
                0.0
            }
        };
        let flag = |on: bool| -> f64 {
            if on {
                1.0
            } else {
                0.0
            }
        };
        [
            (size_kb.log10() / MAX_LOG10_SIZE_KB).clamp(0.0, 1.0),
            (self.max_section_entropy / 8.0).clamp(0.0, 1.0),
            (self.entry_section_entropy / 8.0).clamp(0.0, 1.0),
            (sections / SECTION_COUNT_SCALE).clamp(0.0, 1.0),
            (self.wx_sections as f64 / sections.max(1.0)).clamp(0.0, 1.0),
            flag(self.entry_anomaly),
            ((1.0 + self.import_count as f64).log10() / IMPORT_LOG_SCALE).clamp(0.0, 1.0),
            (self.suspicious_imports.len() as f64 / risky_total).clamp(0.0, 1.0),
            flag(self.signed),
            ratio(self.overlay_bytes as f64, size),
            flag(!self.packer_sections.is_empty()),
            ratio(self.resource_bytes as f64, size),
            flag(self.dotnet),
            flag(self.is_macho()),
        ]
        .map(|value| value as f32)
    }

    /// Plain-English signals behind a high score, strongest first.
    pub fn reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        let few_imports = !self.is_macho() && !self.dotnet && self.import_count <= 10;
        // Compressed resources raise the entropy of benign programs too, so a high-entropy data
        // section only counts as "packed" when there is barely any import table left.
        let packed_entropy = if !self.dotnet && self.import_count <= 20 {
            self.entry_section_entropy.max(self.max_section_entropy)
        } else {
            self.entry_section_entropy
        };
        if packed_entropy >= PACKED_ENTROPY {
            out.push(format!(
                "packed or encrypted code (entropy {packed_entropy:.2}/8)"
            ));
        }
        if !self.packer_sections.is_empty() {
            out.push(format!(
                "packer section names: {}",
                self.packer_sections.join(", ")
            ));
        }
        if self.wx_sections > 0 {
            out.push(format!(
                "{} writable+executable section{}",
                self.wx_sections,
                if self.wx_sections == 1 { "" } else { "s" }
            ));
        }
        if self.entry_anomaly {
            out.push("entry point outside a normal code section".to_string());
        }
        if few_imports {
            out.push(format!("very few imports ({})", self.import_count));
        }
        let risky: Vec<&str> = self
            .suspicious_imports
            .iter()
            .map(String::as_str)
            .filter(|name| *name != COMMON_CRT_IMPORT)
            .collect();
        if !risky.is_empty() {
            out.push(format!("risky APIs: {}", risky.join(", ")));
        }
        if self.size_bytes > 0 {
            let overlay = self.overlay_bytes as f64 / self.size_bytes as f64;
            if overlay >= 0.25 {
                out.push(format!(
                    "large appended data ({:.0}% of the file)",
                    overlay * 100.0
                ));
            }
        }
        if !self.signed {
            out.push("not digitally signed".to_string());
        }
        out
    }
}

/// One scored file: what the model said, what the fallback would say, and the facts behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub score: f32,
    /// "onnx" or "heuristic": which scorer produced `score`.
    pub engine: &'static str,
    /// The fallback score, reported alongside so the two can be compared.
    pub heuristic: f32,
    pub features: FeatureVector,
    pub reasons: Vec<String>,
    pub profile: BinaryProfile,
}

/// Result of `scan_and_respond` for one parsed binary.
#[derive(Debug, Clone, PartialEq)]
pub struct AiOutcome {
    pub score: f32,
    /// Event details (score, engine and reasons) when the file crossed the threshold.
    pub detection: Option<String>,
}

pub struct BinaryAiScanner {
    model: Option<InferenceFn>,
    cache: Mutex<HashMap<PathBuf, (u64, f32)>>,
    fallback_warned: AtomicBool,
    max_scan_bytes: u64,
}

impl BinaryAiScanner {
    pub fn load(model_path: &Path) -> Self {
        match onnx_runtime::load(model_path) {
            Ok(model) => {
                logger::info(format!("ONNX model loaded from {}", model_path.display()));
                Self::build(Some(model))
            }
            Err(e) => {
                logger::warn(format!(
                    "ONNX model unavailable at {} ({e}); using deterministic heuristic scoring",
                    model_path.display()
                ));
                Self::build(None)
            }
        }
    }

    pub fn heuristic_only() -> Self {
        Self::build(None)
    }

    fn build(model: Option<InferenceFn>) -> Self {
        let warned = model.is_none();
        Self {
            model,
            cache: Mutex::new(HashMap::new()),
            fallback_warned: AtomicBool::new(warned),
            max_scan_bytes: MAX_AI_SCAN_BYTES,
        }
    }

    pub fn with_max_scan_bytes(mut self, max_scan_bytes: u64) -> Self {
        self.max_scan_bytes = max_scan_bytes;
        self
    }

    pub fn has_model(&self) -> bool {
        self.model.is_some()
    }

    pub fn engine_name(&self) -> &'static str {
        if self.model.is_some() {
            "onnx"
        } else {
            "heuristic"
        }
    }

    pub fn score_features(&self, features: &FeatureVector) -> f32 {
        if let Some(model) = &self.model {
            if let Some(probability) = model(features).filter(|p| p.is_finite()) {
                return probability.clamp(0.0, 1.0);
            }
            if !self.fallback_warned.swap(true, Ordering::Relaxed) {
                logger::warn("ONNX inference failed; falling back to heuristic scoring");
            }
        }
        heuristic_score(features)
    }

    fn read_binary(&self, path: &Path) -> Option<Vec<u8>> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() == 0 || meta.len() > self.max_scan_bytes {
            return None;
        }
        fs::read(path).ok()
    }

    /// Scores a file (cached by path and mtime); None when it is not a parseable executable,
    /// empty, or too large.
    pub fn scan_file(&self, path: &Path) -> Option<f32> {
        let meta = fs::metadata(path).ok()?;
        let mtime = modified_secs(&meta);
        if let Some(&(cached_mtime, score)) = lock_or_recover(&self.cache).get(path) {
            if cached_mtime == mtime {
                return Some(score);
            }
        }
        let bytes = self.read_binary(path)?;
        let profile = extract_profile(&bytes)?;
        let score = self.score_features(&profile.features());
        let mut cache = lock_or_recover(&self.cache);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), (mtime, score));
        Some(score)
    }

    /// Full, uncached assessment: score plus the facts behind it (detections, `--scan-file`).
    pub fn assess(&self, path: &Path) -> Option<Assessment> {
        let bytes = self.read_binary(path)?;
        let profile = extract_profile(&bytes)?;
        let features = profile.features();
        Some(Assessment {
            score: self.score_features(&features),
            engine: self.engine_name(),
            heuristic: heuristic_score(&features),
            features,
            reasons: profile.reasons(),
            profile,
        })
    }

    /// Event details for a file that scored `score`: re-reads it to explain the verdict.
    pub fn explain(&self, path: &Path, score: f32, threshold: f32) -> String {
        let profile = self.assess(path).map(|a| a.profile);
        detection_details(score, threshold, self.engine_name(), profile.as_ref())
    }
}

pub fn modified_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shannon entropy in bits per byte (0.0..=8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Parser panics on hostile input are contained and treated as "not a binary".
pub fn extract_profile(bytes: &[u8]) -> Option<BinaryProfile> {
    panic::catch_unwind(AssertUnwindSafe(|| match goblin::Object::parse(bytes) {
        Ok(goblin::Object::PE(pe)) => Some(pe_profile(bytes, &pe)),
        Ok(goblin::Object::Mach(mach)) => mach_profile(bytes, &mach),
        _ => None,
    }))
    .ok()
    .flatten()
}

pub fn extract_features(bytes: &[u8]) -> Option<FeatureVector> {
    extract_profile(bytes).map(|profile| profile.features())
}

fn section_slice(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?.min(bytes.len());
    if start >= end {
        None
    } else {
        bytes.get(start..end)
    }
}

/// Mirrors thenex_features.profile_pe.
fn pe_profile(bytes: &[u8], pe: &goblin::pe::PE<'_>) -> BinaryProfile {
    let size = bytes.len() as u64;
    let raw = |s: &goblin::pe::section_table::SectionTable| {
        section_slice(
            bytes,
            s.pointer_to_raw_data as usize,
            s.size_of_raw_data as usize,
        )
    };
    let max_section_entropy = pe
        .sections
        .iter()
        .filter_map(raw)
        .map(shannon_entropy)
        .fold(0.0, f64::max);

    let entry = pe.entry as u64;
    let entry_index = pe.sections.iter().position(|s| {
        let start = u64::from(s.virtual_address);
        let span = u64::from(s.virtual_size.max(s.size_of_raw_data));
        entry >= start && entry < start + span
    });
    let entry_section_entropy = entry_index
        .and_then(|i| raw(&pe.sections[i]))
        .map(shannon_entropy)
        .unwrap_or(0.0);
    let entry_anomaly = entry != 0
        && match entry_index {
            None => true,
            Some(i) => {
                pe.sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE == 0
                    || (pe.sections.len() > 1 && i == pe.sections.len() - 1)
            }
        };
    let wx_sections = pe
        .sections
        .iter()
        .filter(|s| {
            s.characteristics & IMAGE_SCN_MEM_WRITE != 0
                && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        })
        .count();

    let suspicious_imports = SUSPICIOUS_IMPORTS
        .iter()
        .filter(|needle| pe.imports.iter().any(|imp| imp.name.starts_with(**needle)))
        .map(|needle| (*needle).to_string())
        .collect();

    let dirs = pe
        .header
        .optional_header
        .as_ref()
        .map(|oh| &oh.data_directories);
    let present = |dd: Option<&goblin::pe::data_directories::DataDirectory>| {
        dd.filter(|d| d.virtual_address > 0 && d.size > 0).copied()
    };
    let certificate = present(dirs.and_then(|d| d.get_certificate_table()));
    let resources = present(dirs.and_then(|d| d.get_resource_table()));
    let clr = present(dirs.and_then(|d| d.get_clr_runtime_header()));

    let last_end = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data > 0)
        .map(|s| (u64::from(s.pointer_to_raw_data) + u64::from(s.size_of_raw_data)).min(size))
        .max()
        .unwrap_or(0);
    let mut overlay_bytes = size.saturating_sub(last_end);
    if let Some(cert) = certificate {
        if u64::from(cert.virtual_address) >= last_end {
            overlay_bytes -= u64::from(cert.size).min(overlay_bytes);
        }
    }

    let packer_sections = pe
        .sections
        .iter()
        .filter_map(|s| s.name().ok().map(str::to_ascii_lowercase))
        .filter(|name| PACKER_SECTION_NAMES.contains(&name.as_str()))
        .collect();

    BinaryProfile {
        format: "pe",
        size_bytes: size,
        max_section_entropy,
        entry_section_entropy,
        section_count: pe.sections.len(),
        wx_sections,
        entry_anomaly,
        import_count: pe.imports.len(),
        suspicious_imports,
        signed: certificate.is_some(),
        overlay_bytes,
        packer_sections,
        resource_bytes: resources.map(|d| u64::from(d.size).min(size)).unwrap_or(0),
        dotnet: clr.is_some(),
    }
}

/// Mach-O symbols carry a leading underscore; Objective-C classes appear as `_OBJC_CLASS_$_Name`.
fn is_suspicious_macho_symbol(symbol: &str, needle: &str) -> bool {
    symbol.trim_start_matches('_') == needle || symbol.ends_with(&format!("$_{needle}"))
}

#[derive(Default)]
struct MachStats {
    max_entropy: f64,
    text_entropy: f64,
    segments: usize,
    wx_segments: usize,
    imports: usize,
    hits: BTreeSet<&'static str>,
    packers: BTreeSet<String>,
    signed: bool,
}

fn note_packer_name(name: &str, stats: &mut MachStats) {
    let lower = name.to_ascii_lowercase();
    if lower.contains("upx") {
        stats.packers.insert(lower);
    }
}

fn add_macho_slice(macho: &goblin::mach::MachO<'_>, stats: &mut MachStats) {
    use goblin::mach::constants::{VM_PROT_EXECUTE, VM_PROT_WRITE};
    use goblin::mach::load_command::CommandVariant;

    stats.segments = stats.segments.max(macho.segments.len());
    let mut wx = 0;
    for segment in macho.segments.iter() {
        if segment.initprot & VM_PROT_WRITE != 0 && segment.initprot & VM_PROT_EXECUTE != 0 {
            wx += 1;
        }
        if let Ok(name) = segment.name() {
            note_packer_name(name, stats);
        }
        if let Ok(sections) = segment.sections() {
            for (section, data) in sections {
                if let Ok(name) = section.name() {
                    note_packer_name(name, stats);
                }
                if data.is_empty() {
                    continue;
                }
                let entropy = shannon_entropy(data);
                stats.max_entropy = stats.max_entropy.max(entropy);
                if section.name().ok() == Some("__text") && section.segname().ok() == Some("__TEXT")
                {
                    stats.text_entropy = stats.text_entropy.max(entropy);
                }
            }
        }
    }
    stats.wx_segments = stats.wx_segments.max(wx);
    // goblin's imports() reads only the legacy dyld-info tables; binaries linked with chained
    // fixups (every Apple binary since macOS 12) list nothing there. Their undefined external
    // symbols (what `nm -u` prints) are in the symbol table either way, so count both.
    let mut imported: BTreeSet<&str> = BTreeSet::new();
    if let Ok(imports) = macho.imports() {
        imported.extend(imports.iter().map(|imp| imp.name));
    }
    for (name, nlist) in macho.symbols().flatten() {
        if nlist.is_undefined() && nlist.is_global() && !nlist.is_stab() {
            imported.insert(name);
        }
    }
    stats.imports = stats.imports.max(imported.len());
    for needle in SUSPICIOUS_MACHO_SYMBOLS {
        if imported
            .iter()
            .any(|name| is_suspicious_macho_symbol(name, needle))
        {
            stats.hits.insert(needle);
        }
    }
    if macho
        .load_commands
        .iter()
        .any(|lc| matches!(lc.command, CommandVariant::CodeSignature(_)))
    {
        stats.signed = true;
    }
}

/// Fat (multi-arch) binaries combine their slices: maxima of the numeric facts and the union
/// of suspicious symbols and packer names.
fn mach_profile(bytes: &[u8], mach: &goblin::mach::Mach<'_>) -> Option<BinaryProfile> {
    let mut stats = MachStats::default();
    let mut slices = 0;
    match mach {
        goblin::mach::Mach::Binary(macho) => {
            add_macho_slice(macho, &mut stats);
            slices = 1;
        }
        goblin::mach::Mach::Fat(fat) => {
            for index in 0..fat.narches {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(index) {
                    add_macho_slice(&macho, &mut stats);
                    slices += 1;
                }
            }
        }
    }
    (slices > 0).then(|| BinaryProfile {
        format: "macho",
        size_bytes: bytes.len() as u64,
        max_section_entropy: stats.max_entropy,
        entry_section_entropy: stats.text_entropy,
        section_count: stats.segments,
        wx_sections: stats.wx_segments,
        entry_anomaly: false,
        import_count: stats.imports,
        suspicious_imports: stats.hits.iter().map(|s| (*s).to_string()).collect(),
        signed: stats.signed,
        overlay_bytes: 0,
        packer_sections: stats.packers.into_iter().collect(),
        resource_bytes: 0,
        dotnet: false,
    })
}

/// Every feature lies in [0, 1].
pub fn features_in_range(features: &FeatureVector) -> bool {
    features.iter().all(|f| (0.0..=1.0).contains(f))
}

/// Fallback used when the ONNX model is missing: logistic regression over the same features,
/// fitted on the training data. Identical to HEURISTIC_* in scripts/thenex_features.py.
const HEURISTIC_BIAS: f64 = -16.0;
const HEURISTIC_WEIGHTS: [f64; FEATURE_COUNT] = [
    -2.0, 16.5, 7.5, -6.5, 7.5, 1.0, -6.0, 19.0, -2.5, -0.5, 1.0, 2.0, -1.5, -2.5,
];

/// Deterministic logistic score over the same features, used when the model is missing.
pub fn heuristic_score(features: &FeatureVector) -> f32 {
    let z = HEURISTIC_WEIGHTS
        .iter()
        .zip(features)
        .fold(HEURISTIC_BIAS, |z, (weight, value)| {
            z + weight * f64::from(*value)
        });
    (1.0 / (1.0 + (-z).exp())) as f32
}

/// Event details for a detection: the score, then the plain-English reasons.
pub fn detection_details(
    score: f32,
    threshold: f32,
    engine: &str,
    profile: Option<&BinaryProfile>,
) -> String {
    let mut details = format!("score={score:.3} threshold={threshold:.2} engine={engine}");
    if let Some(reasons) = profile.map(BinaryProfile::reasons) {
        if !reasons.is_empty() {
            details.push_str("; ");
            details.push_str(&reasons.join("; "));
        }
    }
    details
}

/// Scores an untrusted binary and quarantines it (or logs, in dry-run) when it crosses the
/// threshold. None when the file is trusted or not a parseable executable.
pub fn scan_and_respond(
    path: &Path,
    cfg: &AppConfig,
    scanner: &BinaryAiScanner,
) -> Option<AiOutcome> {
    if platform::is_trusted_binary(path) {
        return None;
    }
    let score = scanner.scan_file(path)?;
    if score < cfg.ai_threshold {
        return Some(AiOutcome {
            score,
            detection: None,
        });
    }
    // Explain before quarantining: the file is moved away below.
    let details = scanner.explain(path, score, cfg.ai_threshold);
    let action = if cfg.is_dry_run() {
        "DRY_RUN: would quarantine".to_string()
    } else {
        match quarantine::quarantine_file(path, cfg, "MALWARE_AI", &details) {
            Ok(meta) => format!("QUARANTINED id={}", meta.id),
            Err(e) => format!("QUARANTINE_FAILED: {e}"),
        }
    };
    quarantine::record_event(
        cfg,
        ThreatEvent::new(
            "MALWARE_AI",
            Severity::High,
            path.display().to_string(),
            action,
            details.clone(),
        ),
    );
    Some(AiOutcome {
        score,
        detection: Some(details),
    })
}

mod onnx_runtime {
    use super::{FeatureVector, InferenceFn, FEATURE_COUNT};
    use std::path::Path;
    use std::sync::{Mutex, PoisonError};
    use tract_onnx::prelude::*;

    pub fn load(path: &Path) -> Result<InferenceFn, String> {
        if !path.is_file() {
            return Err("file not found".to_string());
        }
        let plan = tract_onnx::onnx()
            .model_for_path(path)
            .and_then(|model| model.with_input_fact(0, f32::fact([1, FEATURE_COUNT]).into()))
            .and_then(|model| model.into_optimized())
            .and_then(|model| model.into_runnable())
            .map_err(|e| e.to_string())?;
        let plan = Mutex::new(plan);
        Ok(Box::new(move |features: &FeatureVector| {
            let input = Tensor::from_shape(&[1, FEATURE_COUNT], features.as_slice()).ok()?;
            let runnable = plan.lock().unwrap_or_else(PoisonError::into_inner);
            let outputs = runnable.run(tvec!(input.into())).ok()?;
            let view = outputs.first()?.to_array_view::<f32>().ok()?;
            view.iter().last().copied()
        }))
    }
}

/// Reference programs, identical to PROTOTYPES in scripts/thenex_features.py.
pub mod prototypes {
    use super::BinaryProfile;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    pub fn signed_app() -> BinaryProfile {
        BinaryProfile {
            size_bytes: 800 * 1024,
            max_section_entropy: 6.4,
            entry_section_entropy: 6.3,
            section_count: 6,
            import_count: 320,
            suspicious_imports: names(&["IsDebuggerPresent"]),
            signed: true,
            resource_bytes: 60 * 1024,
            ..BinaryProfile::default()
        }
    }

    pub fn unsigned_tool() -> BinaryProfile {
        BinaryProfile {
            size_bytes: 600 * 1024,
            max_section_entropy: 6.5,
            entry_section_entropy: 6.4,
            section_count: 8,
            import_count: 180,
            suspicious_imports: names(&["IsDebuggerPresent"]),
            resource_bytes: 5 * 1024,
            ..BinaryProfile::default()
        }
    }

    pub fn packed_injector() -> BinaryProfile {
        BinaryProfile {
            size_bytes: 120 * 1024,
            max_section_entropy: 7.95,
            entry_section_entropy: 7.92,
            section_count: 3,
            wx_sections: 2,
            entry_anomaly: true,
            import_count: 6,
            suspicious_imports: names(&[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "IsDebuggerPresent",
            ]),
            packer_sections: names(&["upx0", "upx1"]),
            resource_bytes: 2 * 1024,
            ..BinaryProfile::default()
        }
    }

    /// (profile, is_malicious)
    pub fn all() -> [(BinaryProfile, bool); 3] {
        [
            (signed_app(), false),
            (unsigned_tool(), false),
            (packed_injector(), true),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 1024]), 0.0);
        let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn features_are_bounded_even_for_absurd_inputs() {
        let absurd = BinaryProfile {
            size_bytes: u64::MAX,
            max_section_entropy: 9.0,
            entry_section_entropy: 9.0,
            section_count: 10_000,
            wx_sections: 20_000,
            entry_anomaly: true,
            import_count: usize::MAX,
            suspicious_imports: vec!["x".to_string(); 50],
            signed: true,
            overlay_bytes: u64::MAX,
            packer_sections: vec!["upx0".to_string()],
            resource_bytes: u64::MAX,
            dotnet: true,
            format: "macho",
        };
        for profile in [BinaryProfile::default(), absurd] {
            let features = profile.features();
            assert!(features_in_range(&features), "{features:?}");
        }
        for (profile, _) in prototypes::all() {
            assert!(features_in_range(&profile.features()));
        }
        // 10 KiB -> log10(10) / 6
        let ten_kb = BinaryProfile {
            size_bytes: 10 * 1024,
            ..BinaryProfile::default()
        };
        assert!((ten_kb.features()[0] - (1.0 / 6.0) as f32).abs() < 1e-6);
    }

    #[test]
    fn heuristic_separates_prototypes() {
        let threshold = crate::config::AI_MALWARE_THRESHOLD;
        for (profile, malicious) in prototypes::all() {
            let score = heuristic_score(&profile.features());
            assert!((0.0..=1.0).contains(&score));
            assert_eq!(score >= threshold, malicious, "{profile:?} scored {score}");
        }
    }

    #[test]
    fn reasons_explain_a_packed_injector_and_stay_quiet_for_a_signed_app() {
        let reasons = prototypes::packed_injector().reasons();
        let text = reasons.join(" | ");
        for expected in [
            "packed or encrypted code (entropy 7.95/8)",
            "packer section names: upx0, upx1",
            "2 writable+executable sections",
            "entry point outside a normal code section",
            "very few imports (6)",
            "risky APIs: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread",
            "not digitally signed",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        assert!(!text.contains("IsDebuggerPresent"), "{text}");
        assert!(prototypes::signed_app().reasons().is_empty());

        let dotnet = BinaryProfile {
            import_count: 1,
            dotnet: true,
            signed: true,
            ..BinaryProfile::default()
        };
        assert!(
            dotnet.reasons().is_empty(),
            ".NET has one import by design: {:?}",
            dotnet.reasons()
        );

        let details = detection_details(0.97, 0.65, "onnx", Some(&prototypes::packed_injector()));
        assert!(details.starts_with("score=0.970 threshold=0.65 engine=onnx; packed"));
    }

    #[test]
    fn non_binaries_have_no_profile() {
        assert_eq!(extract_profile(b"hello world"), None);
        assert_eq!(extract_profile(&[]), None);
        assert_eq!(extract_features(b"MZ"), None);
    }

    #[test]
    fn own_executable_yields_a_sane_profile() {
        let exe = std::env::current_exe().unwrap();
        let profile =
            extract_profile(&fs::read(exe).unwrap()).expect("test binary is a PE or Mach-O image");
        let features = profile.features();
        assert!(features_in_range(&features), "{features:?}");
        let expected_format = if cfg!(target_os = "macos") {
            "macho"
        } else {
            "pe"
        };
        assert_eq!(profile.format, expected_format);
        assert_eq!(
            features[13],
            if cfg!(target_os = "macos") { 1.0 } else { 0.0 }
        );
        assert!(profile.section_count > 0 && profile.max_section_entropy > 0.0);
        assert!(profile.import_count > 0, "{profile:?}");
    }
}
