//! End-to-end scenarios shared by the CLI, the GUI and the tests, and the synthetic activity
//! generators that measure how often the recogniser fires when it should and when it must not.

use crate::device::{ExternalQuery, FormFactor, QueryResponse, SimulatedGnss, Wearable};
use crate::disguise::{self, EXTENSION_LEN, FRAME_LEN};
use crate::ephemeral_crypto::{self, WipeReport, KEY_LEN};
use crate::mesh_relay::{
    Delivery, HopEvent, Link, MeshEnvelope, MeshSim, MeshStats, PhoneEffects, ResponderSink,
    SosAlert,
};
use crate::tap_classifier::{self, RhythmProfile, TapVerdict};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Deterministic generator for reproducible synthetic activity. Never used for keys.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

fn now_unix_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// A calm, textbook performance of the rhythm starting at `start_ms`.
pub fn perform(profile: &RhythmProfile, start_ms: f64) -> Vec<f64> {
    let total = (profile.min_total_ms + profile.max_total_ms) / 2.0;
    let pause = (profile.burst_gap_ms() + profile.max_pause_ms) / 2.0;
    let mut t = start_ms;
    let mut taps = Vec::new();
    for rep in 0..profile.repeats {
        if rep > 0 {
            t += pause;
        }
        taps.push(t);
        for ratio in &profile.ratios {
            t += ratio * total;
            taps.push(t);
        }
    }
    taps
}

/// A person performing the rhythm: random tempo, +/-12% error on every gap, random pauses.
pub fn attempt(rng: &mut SplitMix64, profile: &RhythmProfile) -> Vec<f64> {
    let span = profile.max_total_ms - profile.min_total_ms;
    let (lo, hi) = (
        profile.min_total_ms + 0.15 * span,
        profile.max_total_ms - 0.15 * span,
    );
    let pause_lo = profile.burst_gap_ms() * 1.1;
    let pause_hi = (profile.max_pause_ms * 0.9).max(pause_lo);
    let mut t = rng.range(0.0, 400.0);
    let mut taps = Vec::new();
    for rep in 0..profile.repeats {
        if rep > 0 {
            t += rng.range(pause_lo, pause_hi);
        }
        let total = rng.range(lo, hi);
        taps.push(t);
        for ratio in &profile.ratios {
            t += ratio * total * (1.0 + rng.range(-0.12, 0.12));
            taps.push(t);
        }
    }
    taps
}

/// A hurried or shaky performance: +/-25% error on every gap and +/-20 ms sensor timing noise
/// (a webcam at 30 fps adds about that much).
pub fn sloppy_attempt(rng: &mut SplitMix64, profile: &RhythmProfile) -> Vec<f64> {
    let span = profile.max_total_ms - profile.min_total_ms;
    let (lo, hi) = (
        profile.min_total_ms + 0.15 * span,
        profile.max_total_ms - 0.15 * span,
    );
    let pause_lo = profile.burst_gap_ms() * 1.1;
    let pause_hi = (profile.max_pause_ms * 0.9).max(pause_lo);
    let mut t = rng.range(0.0, 400.0);
    let mut taps = Vec::new();
    for rep in 0..profile.repeats {
        if rep > 0 {
            t += rng.range(pause_lo, pause_hi);
        }
        let total = rng.range(lo, hi);
        taps.push(t + rng.range(-20.0, 20.0));
        for ratio in &profile.ratios {
            t += ratio * total * (1.0 + rng.range(-0.25, 0.25));
            taps.push(t + rng.range(-20.0, 20.0));
        }
    }
    taps
}

/// Footsteps at 92 to 200 steps per minute for 12 s.
pub fn walking(rng: &mut SplitMix64) -> Vec<f64> {
    let period = rng.range(300.0, 650.0);
    let mut t = rng.range(0.0, 300.0);
    let mut taps = Vec::new();
    while t < 12_000.0 {
        taps.push(t);
        t += period * (1.0 + rng.range(-0.06, 0.06));
    }
    taps
}

/// Slow, uneven steps for 15 s.
pub fn strolling(rng: &mut SplitMix64) -> Vec<f64> {
    let period = rng.range(700.0, 1400.0);
    let mut t = rng.range(0.0, 500.0);
    let mut taps = Vec::new();
    while t < 15_000.0 {
        taps.push(t);
        t += period * (1.0 + rng.range(-0.1, 0.1));
    }
    taps
}

/// 30 s of typing: words of 1 to 8 keys, short gaps between words, occasional long pauses.
pub fn typing(rng: &mut SplitMix64) -> Vec<f64> {
    let mut t = 0.0;
    let mut taps = Vec::new();
    while t < 30_000.0 {
        let letters = 1 + rng.below(8);
        for k in 0..letters {
            taps.push(t);
            if k + 1 < letters {
                t += rng.range(90.0, 260.0);
            }
        }
        t += if rng.unit() < 0.15 {
            rng.range(800.0, 2500.0)
        } else {
            rng.range(200.0, 600.0)
        };
    }
    taps
}

/// 20 s of random bumps at 0.5 to 3 per second (Poisson).
pub fn random_taps(rng: &mut SplitMix64) -> Vec<f64> {
    let rate_per_s = rng.range(0.5, 3.0);
    let mut t = 0.0;
    let mut taps = Vec::new();
    loop {
        t += -(1.0 - rng.unit()).ln() / rate_per_s * 1000.0;
        if t >= 20_000.0 {
            break;
        }
        taps.push(t);
    }
    taps
}

/// 20 s of absent-minded single and double taps.
pub fn fidgeting(rng: &mut SplitMix64) -> Vec<f64> {
    let mut t = rng.range(0.0, 500.0);
    let mut taps = Vec::new();
    while t < 20_000.0 {
        taps.push(t);
        if rng.unit() < 0.5 {
            taps.push(t + rng.range(120.0, 300.0));
        }
        t += rng.range(1000.0, 4000.0);
    }
    taps
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalseAcceptRate {
    pub activity: String,
    pub sessions: usize,
    pub session_seconds: f64,
    pub false_accepts: usize,
    pub rate: f64,
    pub per_hour: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Robustness {
    pub profile: String,
    pub trials: usize,
    pub seed: u64,
    pub detected: usize,
    pub detection_rate: f64,
    /// Detection when the rhythm is performed hurriedly or seen through a webcam.
    pub sloppy_detection_rate: f64,
    pub false_accepts: Vec<FalseAcceptRate>,
}

type Generator = fn(&mut SplitMix64) -> Vec<f64>;

/// Monte-Carlo benchmark of a rhythm: how often genuine attempts are recognised and how often
/// everyday activity triggers a false SOS.
pub fn robustness(profile: &RhythmProfile, trials: usize, seed: u64) -> Robustness {
    let trials = trials.clamp(20, 20_000);
    let mut rng = SplitMix64::new(seed);
    let mut detected = 0;
    for _ in 0..trials {
        let taps = attempt(&mut rng, profile);
        if tap_classifier::classify(&taps, profile).accepted {
            detected += 1;
        }
    }
    let mut sloppy = 0;
    for _ in 0..trials {
        let taps = sloppy_attempt(&mut rng, profile);
        if tap_classifier::classify(&taps, profile).accepted {
            sloppy += 1;
        }
    }
    let activities: [(&str, f64, Generator); 5] = [
        ("walking", 12.0, walking),
        ("strolling", 15.0, strolling),
        ("typing", 30.0, typing),
        ("random bumps", 20.0, random_taps),
        ("fidgeting", 20.0, fidgeting),
    ];
    let sessions = (trials / 4).max(10);
    let mut false_accepts = Vec::new();
    for (activity, seconds, generate) in activities {
        let mut hits = 0;
        for _ in 0..sessions {
            let taps = generate(&mut rng);
            if tap_classifier::classify(&taps, profile).accepted {
                hits += 1;
            }
        }
        false_accepts.push(FalseAcceptRate {
            activity: activity.to_string(),
            sessions,
            session_seconds: seconds,
            false_accepts: hits,
            rate: hits as f64 / sessions as f64,
            per_hour: hits as f64 / (sessions as f64 * seconds) * 3600.0,
        });
    }
    Robustness {
        profile: profile.name.clone(),
        trials,
        seed,
        detected,
        detection_rate: detected as f64 / trials as f64,
        sloppy_detection_rate: sloppy as f64 / trials as f64,
        false_accepts,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TapCase {
    pub name: String,
    pub expect_accept: bool,
    pub taps_ms: Vec<f64>,
    pub verdict: TapVerdict,
    pub pass: bool,
}

pub fn tap_cases(profile: &RhythmProfile, seed: u64) -> Vec<TapCase> {
    let mut rng = SplitMix64::new(seed);
    let mut cases: Vec<(String, bool, Vec<f64>)> = vec![
        ("secret rhythm".to_string(), true, perform(profile, 1500.0)),
        (
            "secret rhythm, human timing".to_string(),
            true,
            attempt(&mut rng, profile),
        ),
        ("walking".to_string(), false, walking(&mut rng)),
        ("typing".to_string(), false, typing(&mut rng)),
        ("single tap".to_string(), false, vec![2000.0]),
        ("fidgeting".to_string(), false, fidgeting(&mut rng)),
    ];
    if profile.repeats > 1 {
        let once = RhythmProfile {
            repeats: 1,
            ..profile.clone()
        };
        cases.push((
            "rhythm performed only once".to_string(),
            false,
            perform(&once, 1500.0),
        ));
    }
    cases
        .into_iter()
        .map(|(name, expect_accept, taps_ms)| {
            let verdict = tap_classifier::classify(&taps_ms, profile);
            let pass = verdict.accepted == expect_accept;
            TapCase {
                name,
                expect_accept,
                taps_ms,
                verdict,
                pass,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MeshConfig {
    pub form: FormFactor,
    pub relays: usize,
    pub ttl: u8,
    /// Each relay also reaches the node two hops on: multi-path copies that must be deduplicated.
    pub redundant_links: bool,
    /// The responder comes into range late, so relays must store frames before forwarding.
    pub late_link: bool,
    pub seconds: u64,
    /// Set (to the sign's name) when a camera sign or expression triggers the SOS instead of
    /// the tap rhythm.
    pub camera_sign: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            form: FormFactor::Ring,
            relays: 4,
            ttl: 6,
            redundant_links: true,
            late_link: true,
            seconds: 6,
            camera_sign: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshOutcome {
    pub config: MeshConfig,
    pub nodes: usize,
    pub responder: usize,
    pub links: Vec<Link>,
    pub tap: TapVerdict,
    pub frames_sent: usize,
    pub frame_times_ms: Vec<u64>,
    pub sos_frame_index: Option<usize>,
    pub stats: MeshStats,
    pub alerts: Vec<SosAlert>,
    pub events: Vec<HopEvent>,
    pub phone: PhoneEffects,
    pub wipe: Option<WipeReport>,
    pub retained_location_bytes: usize,
    pub checks: Vec<AuditCheck>,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

fn check(name: &str, passed: bool, detail: impl Into<String>) -> AuditCheck {
    AuditCheck {
        name: name.to_string(),
        passed,
        detail: detail.into(),
    }
}

fn equally_spaced(times: &[u64]) -> bool {
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.windows(2).all(|w| w[0] == w[1])
}

/// A sign recognised by the camera watch queues the same silent SOS as the tap rhythm.
fn camera_trigger(wearable: &mut Wearable, gnss: &SimulatedGnss, sign: &str) -> TapVerdict {
    let queued = wearable.trigger_sos(gnss, now_unix_ms());
    let sign: String = sign.trim().chars().take(40).collect();
    TapVerdict {
        accepted: queued,
        reason: format!("camera sign \"{sign}\" recognised on this device"),
        taps_seen: 0,
        groups: 0,
        deviation: None,
        confidence: if queued { 1.0 } else { 0.0 },
        window_ms: None,
    }
}

/// The wearable is triggered (tap rhythm or camera sign) while frames flow; every frame is
/// relayed hop by hop to the simulated responder.
pub fn mesh_scenario(cfg: &MeshConfig) -> MeshOutcome {
    let relays = cfg.relays.clamp(1, 12);
    let ttl = cfg.ttl.clamp(1, 16);
    let seconds = cfg.seconds.clamp(3, 30);
    let responder = relays + 1;
    let node_count = relays + 2;
    let mut links: Vec<Link> = (0..=relays).map(|i| Link::new(i, i + 1)).collect();
    if cfg.redundant_links {
        links.extend((0..relays).map(|i| Link::new(i, i + 2)));
    }
    if cfg.late_link {
        let late_round = relays as u32 + 2;
        for link in links.iter_mut().filter(|l| l.b == responder) {
            link.up_from_round = late_round;
        }
    }

    let secret = ephemeral_crypto::random_bytes::<KEY_LEN>();
    let mut wearable = Wearable::new(cfg.form, &secret, 0);
    let profile = wearable.profile().clone();
    let gnss = SimulatedGnss::default();
    let mut tap = None;
    let mut frames = Vec::new();
    let mut frame_times_ms = Vec::new();
    let mut sos_frame_index = None;
    let mut now = 0u64;
    while now <= seconds * 1000 {
        if now == 1500 {
            tap = Some(match &cfg.camera_sign {
                Some(sign) => camera_trigger(&mut wearable, &gnss, sign),
                None => wearable.on_taps(&perform(&profile, 0.0), &gnss, now_unix_ms()),
            });
        }
        let pending = wearable.sos_pending();
        if let Some(frame) = wearable.tick(now) {
            if pending && !wearable.sos_pending() {
                sos_frame_index = Some(frames.len());
            }
            frames.push(frame);
            frame_times_ms.push(now);
        }
        now += 10;
    }
    let tap = tap.unwrap_or_else(|| tap_classifier::classify(&[], &profile));

    let mut sim = MeshSim::new(
        node_count,
        links.clone(),
        responder,
        ResponderSink::new(&secret),
    );
    for frame in &frames {
        if let Some(envelope) = MeshEnvelope::from_frame(frame, ttl) {
            sim.inject(0, envelope);
        }
    }
    let stats = sim.run(64).clone();
    let wipe = wearable.last_wipe().cloned();
    let retained = wearable.retained_location_bytes();
    let phone = wearable.phone_effects().clone();

    let mut checks = vec![
        check("trigger recognised", tap.accepted, tap.reason.clone()),
        check(
            "SOS reached the responder exactly once",
            stats.delivered_sos == 1,
            format!(
                "{} delivered in {} hop(s), {} wellness frames discarded",
                stats.delivered_sos, stats.max_hops, stats.wellness_discarded
            ),
        ),
        check(
            "phone stayed silent",
            phone.is_silent(),
            "no notification, vibration, sound or screen wake",
        ),
        check(
            "location wiped after dispatch",
            retained == 0 && wipe.as_ref().is_some_and(|w| w.verified_zero),
            match &wipe {
                Some(w) => format!("{} bytes wiped in {} ns", w.wiped_bytes, w.elapsed_ns),
                None => "no SOS was dispatched".to_string(),
            },
        ),
        check(
            "fixed advertising cadence",
            equally_spaced(&frame_times_ms),
            format!(
                "{} frames, one every {} ms, SOS in slot {}",
                frames.len(),
                wearable.cadence_interval_ms(),
                sos_frame_index.map_or("-".to_string(), |i| i.to_string())
            ),
        ),
    ];
    if cfg.redundant_links {
        checks.push(check(
            "multi-path duplicates dropped",
            stats.duplicates_dropped > 0,
            format!("{} duplicate copies dropped", stats.duplicates_dropped),
        ));
    }
    if cfg.late_link {
        checks.push(check(
            "store-and-forward across a late link",
            stats.stored_then_forwarded > 0,
            format!(
                "{} transmissions waited in a relay's store",
                stats.stored_then_forwarded
            ),
        ));
    }
    let pass = checks.iter().all(|c| c.passed);
    MeshOutcome {
        config: MeshConfig {
            relays,
            ttl,
            seconds,
            ..cfg.clone()
        },
        nodes: node_count,
        responder,
        links,
        tap,
        frames_sent: frames.len(),
        frame_times_ms,
        sos_frame_index,
        alerts: sim.sink.alerts.clone(),
        events: sim.events.clone(),
        stats,
        phone,
        wipe,
        retained_location_bytes: retained,
        checks,
        pass,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZeroizationOutcome {
    pub form: FormFactor,
    pub held_before_dispatch: usize,
    pub wipe: Option<WipeReport>,
    pub dispatch_us: f64,
    pub retained_location_bytes: usize,
    pub pass: bool,
}

/// Limit for "a fraction of a second": generous so slow CI machines pass.
pub const MAX_WIPE_NS: u64 = 50_000_000;

pub fn zeroization_scenario(form: FormFactor) -> ZeroizationOutcome {
    let secret = ephemeral_crypto::random_bytes::<KEY_LEN>();
    let mut wearable = Wearable::new(form, &secret, 0);
    let profile = wearable.profile().clone();
    let verdict = wearable.on_taps(
        &perform(&profile, 0.0),
        &SimulatedGnss::default(),
        now_unix_ms(),
    );
    let held = wearable.retained_location_bytes();
    let started = Instant::now();
    let mut now = 0u64;
    while wearable.sos_pending() && now < 10_000 {
        wearable.tick(now);
        now += 10;
    }
    let dispatch_us = started.elapsed().as_secs_f64() * 1e6;
    let wipe = wearable.last_wipe().cloned();
    let retained = wearable.retained_location_bytes();
    let pass = verdict.accepted
        && held > 0
        && retained == 0
        && wipe
            .as_ref()
            .is_some_and(|w| w.verified_zero && w.elapsed_ns < MAX_WIPE_NS);
    ZeroizationOutcome {
        form,
        held_before_dispatch: held,
        wipe,
        dispatch_us,
        retained_location_bytes: retained,
        pass,
    }
}

fn denied(response: &QueryResponse) -> bool {
    matches!(response, QueryResponse::Denied { .. })
}

fn reason(response: &QueryResponse) -> String {
    match response {
        QueryResponse::Denied { reason } => format!("denied: {reason}"),
        QueryResponse::Status { .. } => "answered".to_string(),
    }
}

/// Privacy and anti-spyware invariants, each checked against the running model.
pub fn privacy_audit(form: FormFactor) -> Vec<AuditCheck> {
    let secret = ephemeral_crypto::random_bytes::<KEY_LEN>();
    let mut wearable = Wearable::new(form, &secret, 0);
    let mut sink = ResponderSink::new(&secret);
    let profile = wearable.profile().clone();
    let mut checks = Vec::new();

    let benign = wearable.tick(0).unwrap_or_default();
    let verdict = wearable.on_taps(
        &perform(&profile, 0.0),
        &SimulatedGnss::default(),
        now_unix_ms(),
    );
    let distress = wearable.tick(1000).unwrap_or_default();
    let after = wearable.tick(2000).unwrap_or_default();
    checks.push(check(
        "silent trigger",
        verdict.accepted && wearable.phone_effects().is_silent(),
        "the tap rhythm queued an SOS without any phone notification, vibration or sound",
    ));

    let same_shape = benign.len() == FRAME_LEN
        && distress.len() == FRAME_LEN
        && benign[..5] == distress[..5]
        && benign[10..12] == distress[10..12]
        && disguise::parse_header(&distress).is_some();
    checks.push(check(
        "SOS looks like step-counter telemetry",
        same_shape,
        format!(
            "same {FRAME_LEN}-byte frame, same header and frame type; only sequence and step count differ"
        ),
    ));

    let deliveries = [
        disguise::extension(&benign).map(|s| sink.deliver(&s, 1)),
        disguise::extension(&distress).map(|s| sink.deliver(&s, 1)),
        disguise::extension(&after).map(|s| sink.deliver(&s, 1)),
    ];
    checks.push(check(
        "only the responder can read it",
        deliveries
            == [
                Some(Delivery::Wellness),
                Some(Delivery::Sos),
                Some(Delivery::Wellness),
            ],
        format!("responder decoded: {deliveries:?}"),
    ));
    let replay = disguise::extension(&distress).map(|s| sink.deliver(&s, 1));
    checks.push(check(
        "replayed SOS rejected",
        replay == Some(Delivery::Rejected) && sink.alerts.len() == 1,
        "a captured SOS frame sent again is refused (one-time token)",
    ));
    let seized = wearable.seized_key();
    let readable =
        disguise::extension(&distress).and_then(|s| disguise::decode_extension(&s, &seized));
    checks.push(check(
        "a seized device cannot read past SOS frames",
        readable.is_none(),
        format!(
            "the key rotated after dispatch (now epoch {}); the old key is gone",
            wearable.epoch()
        ),
    ));
    let wiped = wearable.last_wipe().is_some_and(|w| w.verified_zero);
    checks.push(check(
        "no location retained",
        wiped && wearable.retained_location_bytes() == 0,
        "the fix was zeroized right after its frame left the radio",
    ));

    for (name, query) in [
        (
            "location history cannot be pulled",
            ExternalQuery::LocationHistory,
        ),
        (
            "last location cannot be pulled",
            ExternalQuery::LastKnownLocation,
        ),
        ("no silent audio capture", ExternalQuery::StartAudioCapture),
        ("keys cannot be exported", ExternalQuery::ExportKeys),
    ] {
        let response = wearable.handle_query(&query);
        checks.push(check(name, denied(&response), reason(&response)));
    }
    let interval = wearable.cadence_interval_ms();
    let response = wearable.handle_query(&ExternalQuery::ForceBeacon { interval_ms: 50 });
    checks.push(check(
        "no forced beacon polling",
        denied(&response) && wearable.cadence_interval_ms() == interval,
        reason(&response),
    ));

    let envelope = MeshEnvelope::from_frame(&distress, 4);
    let next = MeshEnvelope::from_frame(&after, 4);
    let fields = envelope
        .as_ref()
        .and_then(|e| serde_json::to_value(e).ok())
        .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()))
        .unwrap_or_default();
    let mut fields = fields;
    fields.sort();
    let unlinkable = match (&envelope, &next) {
        (Some(a), Some(b)) => a.id() != b.id() && a.to_bytes().len() == 1 + EXTENSION_LEN,
        _ => false,
    };
    checks.push(check(
        "relays see no origin or destination",
        fields == ["sealed", "ttl"] && unlinkable,
        "an envelope is a hop counter plus opaque sealed bytes; consecutive frames share nothing",
    ));

    let mut control = Wearable::new(form, &secret, 0);
    control.low_battery_warning();
    checks.push(check(
        "phone-effect recorder works",
        !control.phone_effects().is_silent() && wearable.phone_effects().is_silent(),
        "an ordinary low-battery warning does reach the phone; the SOS path never does",
    ));
    checks
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FramePreview {
    pub frame_len: usize,
    pub header_len: usize,
    pub wellness_hex: String,
    pub sos_hex: String,
    pub same_header_shape: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A wellness frame and an SOS frame side by side, as a radio scanner would capture them.
pub fn frame_preview(form: FormFactor) -> FramePreview {
    let secret = ephemeral_crypto::random_bytes::<KEY_LEN>();
    let mut wearable = Wearable::new(form, &secret, 0);
    let profile = wearable.profile().clone();
    let wellness = wearable.tick(0).unwrap_or_default();
    wearable.on_taps(
        &perform(&profile, 0.0),
        &SimulatedGnss::default(),
        now_unix_ms(),
    );
    let sos = wearable.tick(1000).unwrap_or_default();
    FramePreview {
        frame_len: FRAME_LEN,
        header_len: disguise::HEADER_LEN,
        same_header_shape: wellness.len() == FRAME_LEN
            && sos.len() == FRAME_LEN
            && wellness[..5] == sos[..5],
        wellness_hex: hex(&wellness),
        sos_hex: hex(&sos),
    }
}
