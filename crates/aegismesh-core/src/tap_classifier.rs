//! Recognises a secret tap rhythm (for example: triple tap against the palm, pause, triple tap)
//! from tap timestamps, and rejects walking, typing, fidgeting and stray taps.
//!
//! Taps are grouped by pauses. A group matches when it has the right number of taps, lasts a
//! plausible time and its gaps are in the calibrated proportions (tempo does not matter). The
//! rhythm must be performed `repeats` times in a row and be isolated from other activity.

use serde::{Deserialize, Serialize};

/// Taps closer than this are one physical tap (sensor ringing, camera double-detections).
pub const DEBOUNCE_MS: f64 = 40.0;
pub const MIN_TAPS: usize = 3;
pub const MAX_TAPS: usize = 8;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RhythmProfile {
    pub name: String,
    /// Each gap between consecutive taps as a fraction of the whole gesture (sums to 1).
    pub ratios: Vec<f64>,
    /// Largest allowed difference between a measured and an expected gap fraction.
    pub tolerance: f64,
    pub min_total_ms: f64,
    pub max_total_ms: f64,
    /// Faster gaps are bounce or vibration, not deliberate taps.
    pub min_gap_ms: f64,
    /// How many times the rhythm must be performed in a row.
    pub repeats: u32,
    /// Longest pause allowed between repeats.
    pub max_pause_ms: f64,
    /// Stillness required before and after the whole gesture.
    pub quiet_ms: f64,
}

impl Default for RhythmProfile {
    fn default() -> Self {
        Self::triple_tap()
    }
}

impl RhythmProfile {
    pub fn triple_tap() -> Self {
        Self {
            name: "Triple tap, twice".to_string(),
            ratios: vec![0.5, 0.5],
            tolerance: 0.16,
            min_total_ms: 160.0,
            max_total_ms: 900.0,
            min_gap_ms: 60.0,
            repeats: 2,
            max_pause_ms: 3000.0,
            quiet_ms: 1300.0,
        }
    }

    pub fn taps(&self) -> usize {
        self.ratios.len() + 1
    }

    /// A gap at least this long ends one tap group.
    pub fn burst_gap_ms(&self) -> f64 {
        let widest = self.ratios.iter().copied().fold(0.0, f64::max);
        (self.max_total_ms * widest * (1.0 + self.tolerance) * 1.2).max(250.0)
    }

    pub fn validate(&self) -> Result<(), String> {
        let taps = self.taps();
        if !(MIN_TAPS..=MAX_TAPS).contains(&taps) {
            return Err(format!(
                "a rhythm needs {MIN_TAPS} to {MAX_TAPS} taps, this one has {taps}"
            ));
        }
        if self.ratios.iter().any(|r| !r.is_finite() || *r <= 0.0) {
            return Err("every gap in the rhythm must be positive".to_string());
        }
        let sum: f64 = self.ratios.iter().sum();
        if (sum - 1.0).abs() > 1e-3 {
            return Err(format!("rhythm gaps must add up to 1, not {sum:.3}"));
        }
        if !(0.02..=0.45).contains(&self.tolerance) {
            return Err("tolerance must be between 0.02 and 0.45".to_string());
        }
        if !(self.min_total_ms > 0.0 && self.min_total_ms < self.max_total_ms) {
            return Err("the shortest gesture must be shorter than the longest".to_string());
        }
        if !(self.min_gap_ms > 0.0 && self.min_gap_ms.is_finite()) {
            return Err("the minimum gap must be positive".to_string());
        }
        if !(1..=4).contains(&self.repeats) {
            return Err("repeat the rhythm 1 to 4 times".to_string());
        }
        let burst_gap = self.burst_gap_ms();
        if self.quiet_ms < burst_gap {
            return Err(format!(
                "stillness before and after must be at least {burst_gap:.0} ms"
            ));
        }
        if self.repeats > 1 && self.max_pause_ms < burst_gap {
            return Err(format!(
                "the pause between repeats must allow at least {burst_gap:.0} ms"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TapVerdict {
    pub accepted: bool,
    pub reason: String,
    pub taps_seen: usize,
    pub groups: usize,
    /// Worst gap-fraction error of the matched (or closest) group.
    pub deviation: Option<f64>,
    /// 0..1: how far inside the tolerance the match was.
    pub confidence: f64,
    /// Start and end of the accepted gesture, in the input's time base.
    pub window_ms: Option<(f64, f64)>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GroupFit {
    Match(f64),
    Rhythm(f64),
    WrongCount,
    TooFast,
    Tempo,
}

/// Sorted, finite, debounced tap times.
pub fn clean_taps(times_ms: &[f64]) -> Vec<f64> {
    let mut taps: Vec<f64> = times_ms.iter().copied().filter(|t| t.is_finite()).collect();
    taps.sort_by(f64::total_cmp);
    let mut out: Vec<f64> = Vec::with_capacity(taps.len());
    for t in taps {
        let bounce = out.last().is_some_and(|last| t - last < DEBOUNCE_MS);
        if !bounce {
            out.push(t);
        }
    }
    out
}

fn split_groups(taps: &[f64], gap_ms: f64) -> Vec<Vec<f64>> {
    let mut groups: Vec<Vec<f64>> = Vec::new();
    for &t in taps {
        let starts_new = groups
            .last()
            .and_then(|group| group.last())
            .map_or(true, |last| t - last >= gap_ms);
        if starts_new {
            groups.push(vec![t]);
        } else if let Some(group) = groups.last_mut() {
            group.push(t);
        }
    }
    groups
}

fn first(group: &[f64]) -> f64 {
    group[0]
}

fn last(group: &[f64]) -> f64 {
    group[group.len() - 1]
}

fn fit(group: &[f64], profile: &RhythmProfile) -> GroupFit {
    if group.len() != profile.taps() {
        return GroupFit::WrongCount;
    }
    let total = last(group) - first(group);
    if total < profile.min_total_ms || total > profile.max_total_ms {
        return GroupFit::Tempo;
    }
    let gaps: Vec<f64> = group.windows(2).map(|w| w[1] - w[0]).collect();
    if gaps.iter().any(|g| *g < profile.min_gap_ms) {
        return GroupFit::TooFast;
    }
    let deviation = gaps
        .iter()
        .zip(&profile.ratios)
        .map(|(gap, ratio)| (gap / total - ratio).abs())
        .fold(0.0, f64::max);
    if deviation <= profile.tolerance {
        GroupFit::Match(deviation)
    } else {
        GroupFit::Rhythm(deviation)
    }
}

pub fn classify(times_ms: &[f64], profile: &RhythmProfile) -> TapVerdict {
    let taps = clean_taps(times_ms);
    let mut verdict = TapVerdict {
        accepted: false,
        reason: String::new(),
        taps_seen: taps.len(),
        groups: 0,
        deviation: None,
        confidence: 0.0,
        window_ms: None,
    };
    if let Err(e) = profile.validate() {
        verdict.reason = format!("invalid rhythm: {e}");
        return verdict;
    }
    if taps.is_empty() {
        verdict.reason = "no taps".to_string();
        return verdict;
    }
    let groups = split_groups(&taps, profile.burst_gap_ms());
    let fits: Vec<GroupFit> = groups.iter().map(|g| fit(g, profile)).collect();
    verdict.groups = groups.len();
    let repeats = profile.repeats as usize;

    let mut isolated_failure = false;
    for start in 0..groups.len() {
        let end = start + repeats;
        if end > groups.len() {
            break;
        }
        let deviations: Option<Vec<f64>> = fits[start..end]
            .iter()
            .map(|f| match f {
                GroupFit::Match(d) => Some(*d),
                _ => None,
            })
            .collect();
        let Some(deviations) = deviations else {
            continue;
        };
        let paused_ok = (start + 1..end)
            .all(|i| first(&groups[i]) - last(&groups[i - 1]) <= profile.max_pause_ms);
        let begin_ms = first(&groups[start]);
        let end_ms = last(&groups[end - 1]);
        let before_ok = start == 0 || begin_ms - last(&groups[start - 1]) >= profile.quiet_ms;
        let after_ok = end == groups.len() || first(&groups[end]) - end_ms >= profile.quiet_ms;
        if !(paused_ok && before_ok && after_ok) {
            isolated_failure = true;
            continue;
        }
        let deviation = deviations.iter().copied().fold(0.0, f64::max);
        verdict.accepted = true;
        verdict.deviation = Some(deviation);
        verdict.confidence = (1.0 - deviation / profile.tolerance).clamp(0.0, 1.0);
        verdict.window_ms = Some((begin_ms, end_ms));
        verdict.reason = format!(
            "rhythm recognised, performed {repeats}x ({:.0}% off at worst)",
            deviation * 100.0
        );
        return verdict;
    }

    let closest = fits
        .iter()
        .filter_map(|f| match f {
            GroupFit::Match(d) | GroupFit::Rhythm(d) => Some(*d),
            _ => None,
        })
        .fold(f64::INFINITY, f64::min);
    if closest.is_finite() {
        verdict.deviation = Some(closest);
    }
    let longest = groups.iter().map(Vec::len).max().unwrap_or(0);
    let matched = fits
        .iter()
        .filter(|f| matches!(f, GroupFit::Match(_)))
        .count();
    verdict.reason = if longest > profile.taps() + 2 {
        format!("continuous tapping ({longest} taps without a pause), like walking or typing")
    } else if isolated_failure {
        format!(
            "the rhythm needs {:.1} s of stillness around it and at most {:.1} s between repeats",
            profile.quiet_ms / 1000.0,
            profile.max_pause_ms / 1000.0
        )
    } else if matched > 0 {
        format!(
            "rhythm recognised {matched} time(s); perform it {repeats} times with a short pause ({:.1}–{:.1} s)",
            profile.burst_gap_ms() / 1000.0,
            profile.max_pause_ms / 1000.0
        )
    } else if fits.iter().any(|f| matches!(f, GroupFit::Rhythm(_))) {
        format!(
            "rhythm differs from the calibrated one ({:.0}% off, {:.0}% allowed)",
            closest * 100.0,
            profile.tolerance * 100.0
        )
    } else if fits.iter().any(|f| matches!(f, GroupFit::TooFast)) {
        format!(
            "taps closer than {:.0} ms look like vibration, not deliberate taps",
            profile.min_gap_ms
        )
    } else if fits.iter().any(|f| matches!(f, GroupFit::Tempo)) {
        format!(
            "too fast or too slow: one rhythm should take {:.0}–{:.0} ms",
            profile.min_total_ms, profile.max_total_ms
        )
    } else if longest == 1 {
        "single taps only".to_string()
    } else {
        format!(
            "{} taps do not form the {}-tap rhythm",
            taps.len(),
            profile.taps()
        )
    };
    verdict
}

/// Builds a profile from at least three recordings of one rhythm (one performance each).
pub fn calibrate(samples: &[Vec<f64>], name: &str, repeats: u32) -> Result<RhythmProfile, String> {
    if samples.len() < 3 {
        return Err("record the rhythm at least 3 times".to_string());
    }
    let cleaned: Vec<Vec<f64>> = samples.iter().map(|s| clean_taps(s)).collect();
    let taps = cleaned[0].len();
    if !(MIN_TAPS..=MAX_TAPS).contains(&taps) {
        return Err(format!(
            "use {MIN_TAPS} to {MAX_TAPS} taps; the first recording has {taps}"
        ));
    }
    if let Some((i, sample)) = cleaned.iter().enumerate().find(|(_, s)| s.len() != taps) {
        return Err(format!(
            "recording {} has {} taps but the first has {taps}; tap the same rhythm each time",
            i + 1,
            sample.len()
        ));
    }
    let mut normalized: Vec<Vec<f64>> = Vec::new();
    let mut totals: Vec<f64> = Vec::new();
    let mut min_gap = f64::INFINITY;
    for sample in &cleaned {
        let total = last(sample) - first(sample);
        let gaps: Vec<f64> = sample.windows(2).map(|w| w[1] - w[0]).collect();
        min_gap = gaps.iter().copied().fold(min_gap, f64::min);
        normalized.push(gaps.iter().map(|g| g / total).collect());
        totals.push(total);
    }
    let count = normalized.len() as f64;
    let mut ratios: Vec<f64> = (0..taps - 1)
        .map(|j| normalized.iter().map(|r| r[j]).sum::<f64>() / count)
        .collect();
    let spread = (0..taps - 1)
        .map(|j| {
            let variance = normalized
                .iter()
                .map(|r| (r[j] - ratios[j]).powi(2))
                .sum::<f64>()
                / count;
            variance.sqrt()
        })
        .fold(0.0, f64::max);
    let worst = normalized
        .iter()
        .flat_map(|r| r.iter().zip(&ratios).map(|(a, b)| (a - b).abs()))
        .fold(0.0, f64::max);
    if worst > 0.2 {
        return Err(format!(
            "the recordings disagree (one is {:.0}% off the average); tap the same rhythm each time",
            worst * 100.0
        ));
    }
    let max_total = totals.iter().copied().fold(0.0, f64::max);
    let min_total = totals.iter().copied().fold(f64::INFINITY, f64::min);
    if max_total > 3000.0 {
        return Err("too slow: keep one rhythm under 3 seconds".to_string());
    }
    let sum: f64 = ratios.iter().sum();
    for ratio in &mut ratios {
        *ratio /= sum;
    }
    let mut profile = RhythmProfile {
        name: name.trim().chars().take(60).collect(),
        ratios,
        tolerance: (0.06 + 2.5 * spread).clamp(0.10, 0.20),
        min_total_ms: (min_total * 0.6).max(100.0),
        max_total_ms: max_total * 1.6,
        min_gap_ms: (min_gap * 0.5).clamp(30.0, 120.0),
        repeats,
        max_pause_ms: 3000.0,
        quiet_ms: 1300.0,
    };
    if profile.name.is_empty() {
        profile.name = "Calibrated rhythm".to_string();
    }
    let burst_gap = profile.burst_gap_ms();
    profile.quiet_ms = profile.quiet_ms.max(burst_gap * 1.2);
    profile.max_pause_ms = profile.max_pause_ms.max(burst_gap * 2.0);
    profile.validate()?;
    Ok(profile)
}
