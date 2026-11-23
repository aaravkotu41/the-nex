//! Turns a camera's per-frame motion energy into tap times, so the rhythm recogniser can be
//! tested with a webcam instead of a wearable's accelerometer.
//!
//! The frontend reports, for each video frame, the mean absolute brightness change inside a
//! region of interest (0..255, with the frame's overall brightness change removed so exposure
//! shifts do not count). Each tap is a local peak above an adaptive threshold (median plus a
//! multiple of the median absolute deviation, so lighting and camera noise set the baseline)
//! that rises clearly above the valley before it. Peaks closer than the refractory period are
//! one tap (a finger's down and up strokes). The tap time is where the rise first reaches a
//! quarter of its height, interpolated between frames, so every tap is timed the same way.

use serde::{Deserialize, Serialize};

/// A peak must rise this fraction of its height above the preceding valley.
const PROMINENCE: f64 = 0.35;
/// Tap time = when the rise reaches this fraction of its height.
const ONSET_LEVEL: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MotionSample {
    pub t_ms: f64,
    pub energy: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OnsetConfig {
    /// Threshold = baseline + sensitivity * robust noise (higher = fewer, stronger taps).
    pub sensitivity: f64,
    /// Smallest rise above the baseline that can count as a tap.
    pub min_rise: f64,
    /// Peaks closer than this are one tap.
    pub refractory_ms: f64,
}

impl Default for OnsetConfig {
    fn default() -> Self {
        Self {
            sensitivity: 5.0,
            min_rise: 3.0,
            refractory_ms: 130.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnsetReport {
    pub taps_ms: Vec<f64>,
    pub peaks: Vec<f64>,
    pub baseline: f64,
    pub threshold: f64,
    pub frames: usize,
    pub fps: f64,
    pub warning: Option<String>,
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

pub fn detect_taps(samples: &[MotionSample], cfg: &OnsetConfig) -> OnsetReport {
    let mut frames: Vec<MotionSample> = samples
        .iter()
        .copied()
        .filter(|s| s.t_ms.is_finite() && s.energy.is_finite())
        .collect();
    frames.sort_by(|a, b| a.t_ms.total_cmp(&b.t_ms));
    let energies: Vec<f64> = frames.iter().map(|s| s.energy.max(0.0)).collect();
    let times: Vec<f64> = frames.iter().map(|s| s.t_ms).collect();
    let baseline = median(&mut energies.clone());
    let mut deviations: Vec<f64> = energies.iter().map(|e| (e - baseline).abs()).collect();
    let noise = median(&mut deviations) * 1.4826;
    let min_rise = cfg.min_rise.max(0.1);
    let threshold = baseline + (cfg.sensitivity.max(0.5) * noise).max(min_rise);
    let refractory = cfg.refractory_ms.max(0.0);

    // (onset time, peak time, peak value)
    let mut taps: Vec<(f64, f64, f64)> = Vec::new();
    let mut valley = energies.first().copied().unwrap_or(0.0);
    let mut valley_at = 0usize;
    for i in 1..energies.len().saturating_sub(1) {
        let e = energies[i];
        if e < valley {
            valley = e;
            valley_at = i;
        }
        let is_peak = e >= threshold && e >= energies[i - 1] && e > energies[i + 1];
        let rise = e - valley;
        if !is_peak || rise < (PROMINENCE * (e - baseline)).max(min_rise * 0.5) {
            continue;
        }
        let level = valley + ONSET_LEVEL * rise;
        let mut j = i;
        while j > valley_at && energies[j - 1] >= level {
            j -= 1;
        }
        let onset = if j == 0 {
            times[0]
        } else {
            let (a, b) = (energies[j - 1], energies[j]);
            if b > a {
                times[j - 1] + (level - a) / (b - a) * (times[j] - times[j - 1])
            } else {
                times[j]
            }
        };
        let merge = taps
            .last()
            .is_some_and(|last| times[i] - last.1 < refractory);
        if merge {
            if let Some(last) = taps.last_mut() {
                if e > last.2 {
                    last.1 = times[i];
                    last.2 = e;
                }
            }
        } else {
            taps.push((onset, times[i], e));
        }
        valley = e;
        valley_at = i;
    }

    let span = match (times.first(), times.last()) {
        (Some(a), Some(b)) => b - a,
        _ => 0.0,
    };
    let fps = if span > 0.0 {
        (times.len() - 1) as f64 * 1000.0 / span
    } else {
        0.0
    };
    let warning = if frames.len() < 10 {
        Some("too few camera frames; record for a few seconds".to_string())
    } else if fps < 15.0 {
        Some(format!(
            "camera delivered {fps:.0} fps; quick taps may be missed (add light or close other camera apps)"
        ))
    } else if span > 0.0 && taps.len() as f64 > span / 1000.0 * 6.0 {
        Some("constant motion in view; keep only your tapping hand in the box".to_string())
    } else {
        None
    };
    OnsetReport {
        taps_ms: taps.iter().map(|t| t.0).collect(),
        peaks: taps.iter().map(|t| t.2).collect(),
        baseline,
        threshold,
        frames: frames.len(),
        fps,
        warning,
    }
}
