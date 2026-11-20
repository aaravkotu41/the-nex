use crate::config::{AppConfig, MAX_AI_SCAN_BYTES};
use crate::logger::{self, lock_or_recover};
use crate::platform;
use crate::quarantine::{self, Severity, ThreatEvent};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

pub const FEATURE_COUNT: usize = 4;
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "log10_size_kb",
    "max_section_entropy_norm",
    "section_count_norm",
    "suspicious_import_ratio",
];
pub const SUSPICIOUS_IMPORTS: [&str; 9] = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "URLDownloadToFile",
    "IsDebuggerPresent",
    "WinExec",
    "ShellExecute",
];
pub const SUSPICIOUS_MACHO_SYMBOLS: [&str; 7] = [
    "dlopen", "ptrace", "NSTask", "system", "popen", "execve", "mprotect",
];
/// Feature 0 is log10 of the size in KiB (floored at 1 KiB): 10 KB -> 1.0, 3 MB -> 3.5, capped at 1 GiB.
pub const MAX_LOG10_SIZE_KB: f32 = 6.0;
const SECTION_COUNT_SCALE: f64 = 16.0;
const MAX_CACHE_ENTRIES: usize = 4096;

pub type FeatureVector = [f32; FEATURE_COUNT];
/// Wraps the optimized tract `SimplePlan`; returns P(malicious) or None on inference failure.
type InferenceFn = Box<dyn Fn(&FeatureVector) -> Option<f32> + Send + Sync>;

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

    /// Scores a PE file; None when the file is not a parseable binary, empty, or too large.
    pub fn scan_file(&self, path: &Path) -> Option<f32> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() == 0 || meta.len() > self.max_scan_bytes {
            return None;
        }
        let mtime = modified_secs(&meta);
        if let Some(&(cached_mtime, score)) = lock_or_recover(&self.cache).get(path) {
            if cached_mtime == mtime {
                return Some(score);
            }
        }
        let bytes = fs::read(path).ok()?;
        let features = extract_features(&bytes)?;
        let score = self.score_features(&features);
        let mut cache = lock_or_recover(&self.cache);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), (mtime, score));
        Some(score)
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

pub fn feature_vector(
    size_bytes: u64,
    max_section_entropy: f64,
    section_count: usize,
    suspicious_hits: usize,
    suspicious_total: usize,
) -> FeatureVector {
    let size_kb = size_bytes as f64 / 1024.0;
    let size = size_kb
        .max(1.0)
        .log10()
        .clamp(0.0, f64::from(MAX_LOG10_SIZE_KB));
    let entropy = (max_section_entropy / 8.0).clamp(0.0, 1.0);
    let sections = (section_count as f64 / SECTION_COUNT_SCALE).clamp(0.0, 1.0);
    let suspicious = if suspicious_total == 0 {
        0.0
    } else {
        (suspicious_hits as f64 / suspicious_total as f64).clamp(0.0, 1.0)
    };
    [
        size as f32,
        entropy as f32,
        sections as f32,
        suspicious as f32,
    ]
}

/// Parser panics on hostile input are contained and treated as "not a binary".
pub fn extract_features(bytes: &[u8]) -> Option<FeatureVector> {
    panic::catch_unwind(AssertUnwindSafe(|| match goblin::Object::parse(bytes) {
        Ok(goblin::Object::PE(pe)) => Some(pe_features(bytes, &pe)),
        Ok(goblin::Object::Mach(mach)) => mach_features(bytes, &mach),
        _ => None,
    }))
    .ok()
    .flatten()
}

fn section_slice(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?.min(bytes.len());
    if start >= end {
        None
    } else {
        bytes.get(start..end)
    }
}

fn pe_features(bytes: &[u8], pe: &goblin::pe::PE<'_>) -> FeatureVector {
    let max_entropy = pe
        .sections
        .iter()
        .filter_map(|s| {
            section_slice(
                bytes,
                s.pointer_to_raw_data as usize,
                s.size_of_raw_data as usize,
            )
        })
        .map(shannon_entropy)
        .fold(0.0, f64::max);
    let hits = SUSPICIOUS_IMPORTS
        .iter()
        .filter(|needle| pe.imports.iter().any(|imp| imp.name.starts_with(**needle)))
        .count();
    feature_vector(
        bytes.len() as u64,
        max_entropy,
        pe.sections.len(),
        hits,
        SUSPICIOUS_IMPORTS.len(),
    )
}

/// Mach-O symbols carry a leading underscore; Objective-C classes appear as `_OBJC_CLASS_$_Name`.
fn is_suspicious_macho_symbol(symbol: &str, needle: &str) -> bool {
    symbol.trim_start_matches('_') == needle || symbol.ends_with(&format!("$_{needle}"))
}

struct MachStats {
    max_entropy: f64,
    segments: usize,
    hits: BTreeSet<&'static str>,
}

fn add_macho_slice(macho: &goblin::mach::MachO<'_>, stats: &mut MachStats) {
    stats.segments = stats.segments.max(macho.segments.len());
    for segment in macho.segments.iter() {
        if let Ok(sections) = segment.sections() {
            for (_, data) in sections {
                if !data.is_empty() {
                    stats.max_entropy = stats.max_entropy.max(shannon_entropy(data));
                }
            }
        }
    }
    if let Ok(imports) = macho.imports() {
        for needle in SUSPICIOUS_MACHO_SYMBOLS {
            if imports
                .iter()
                .any(|imp| is_suspicious_macho_symbol(imp.name, needle))
            {
                stats.hits.insert(needle);
            }
        }
    }
}

/// Same four features as PE. Fat (multi-arch) binaries combine their slices: max section
/// entropy, max segment count and the union of suspicious symbols.
fn mach_features(bytes: &[u8], mach: &goblin::mach::Mach<'_>) -> Option<FeatureVector> {
    let mut stats = MachStats {
        max_entropy: 0.0,
        segments: 0,
        hits: BTreeSet::new(),
    };
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
    (slices > 0).then(|| {
        feature_vector(
            bytes.len() as u64,
            stats.max_entropy,
            stats.segments,
            stats.hits.len(),
            SUSPICIOUS_MACHO_SYMBOLS.len(),
        )
    })
}

/// Feature 0 within [0, MAX_LOG10_SIZE_KB]; the other three within [0, 1].
pub fn features_in_range(features: &FeatureVector) -> bool {
    (0.0..=MAX_LOG10_SIZE_KB).contains(&features[0])
        && features[1..].iter().all(|f| (0.0..=1.0).contains(f))
}

/// Deterministic logistic score over the same four features (used when the model is absent).
pub fn heuristic_score(features: &FeatureVector) -> f32 {
    let [size, entropy, sections, suspicious] = features.map(f64::from);
    let z = -8.5 + 7.5 * entropy + 7.0 * suspicious - 1.5 * sections - 0.17 * size;
    (1.0 / (1.0 + (-z).exp())) as f32
}

pub fn scan_and_respond(path: &Path, cfg: &AppConfig, scanner: &BinaryAiScanner) -> Option<f32> {
    if platform::is_trusted_binary(path) {
        return None;
    }
    let score = scanner.scan_file(path)?;
    if score < cfg.ai_threshold {
        return Some(score);
    }
    let details = format!(
        "score={score:.3} threshold={:.2} engine={}",
        cfg.ai_threshold,
        scanner.engine_name()
    );
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
            details,
        ),
    );
    Some(score)
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
    fn feature_vector_is_bounded() {
        for features in [
            feature_vector(0, 0.0, 0, 0, 9),
            feature_vector(u64::MAX, 9.0, 1000, 50, 9),
            feature_vector(350 * 1024, 6.4, 6, 1, 9),
            feature_vector(10, 3.0, 2, 0, 0),
        ] {
            assert!(features_in_range(&features), "{features:?}");
        }
        assert!((feature_vector(10 * 1024, 0.0, 0, 0, 9)[0] - 1.0).abs() < 1e-6);
        assert_eq!(feature_vector(u64::MAX, 0.0, 0, 0, 9)[0], MAX_LOG10_SIZE_KB);
    }

    #[test]
    fn heuristic_separates_prototypes() {
        let threshold = crate::config::AI_MALWARE_THRESHOLD;
        for (features, malicious) in [
            (feature_vector(800 * 1024, 6.3, 6, 1, 9), false),
            (feature_vector(120 * 1024, 7.9, 3, 5, 9), true),
            ([3.5, 0.55, 0.3, 0.0], false),
            ([1.0, 0.98, 0.1, 0.9], true),
        ] {
            let score = heuristic_score(&features);
            assert!((0.0..=1.0).contains(&score));
            assert_eq!(score >= threshold, malicious, "{features:?} scored {score}");
        }
    }

    #[test]
    fn non_binaries_have_no_features() {
        assert_eq!(extract_features(b"hello world"), None);
        assert_eq!(extract_features(&[]), None);
    }

    #[test]
    fn own_executable_yields_bounded_features() {
        let exe = std::env::current_exe().unwrap();
        let bytes = fs::read(exe).unwrap();
        let features = extract_features(&bytes).expect("test binary is a PE or Mach-O image");
        assert!(features_in_range(&features), "{features:?}");
    }

    /// Runs when THENEX_MODEL_PATH points at a model produced by train_onnx.py (CI sets it).
    #[test]
    fn trained_model_loads_in_tract_and_separates_prototypes() {
        let Some(path) = std::env::var_os("THENEX_MODEL_PATH") else {
            eprintln!("THENEX_MODEL_PATH not set; skipping ONNX model check");
            return;
        };
        let scanner = BinaryAiScanner::load(Path::new(&path));
        let infer = scanner
            .model
            .as_ref()
            .unwrap_or_else(|| panic!("tract could not load {path:?}"));
        let benign =
            infer(&feature_vector(800 * 1024, 6.3, 6, 1, 9)).expect("ONNX inference failed");
        let malicious =
            infer(&feature_vector(120 * 1024, 7.9, 3, 5, 9)).expect("ONNX inference failed");
        assert!((0.0..=1.0).contains(&benign) && (0.0..=1.0).contains(&malicious));
        assert!(
            benign < crate::config::AI_MALWARE_THRESHOLD,
            "benign={benign}"
        );
        assert!(
            malicious >= crate::config::AI_MALWARE_THRESHOLD,
            "malicious={malicious}"
        );
    }

    #[test]
    fn missing_model_falls_back_to_heuristic() {
        let scanner = BinaryAiScanner::load(Path::new("definitely-missing-model.onnx"));
        assert!(!scanner.has_model());
        let features = feature_vector(120 * 1024, 7.9, 3, 5, 9);
        assert_eq!(
            scanner.score_features(&features),
            heuristic_score(&features)
        );
    }
}
