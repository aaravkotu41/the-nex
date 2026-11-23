//! AegisMesh suite: tap recognition, disguise, mesh relay, zeroization and anti-spyware
//! invariants, all against in-memory simulations.

use aegismesh_core::camera_taps::{self, MotionSample, OnsetConfig};
use aegismesh_core::console;
use aegismesh_core::device::{ExternalQuery, FormFactor, QueryResponse, SimulatedGnss, Wearable};
use aegismesh_core::disguise::{
    self, Decoded, Telemetry, EXTENSION_LEN, FRAME_LEN, HEADER_LEN, PLAINTEXT_LEN,
};
use aegismesh_core::ephemeral_crypto::{self, DispatchBuffers, KeyRatchet, LocationFix, KEY_LEN};
use aegismesh_core::mesh_relay::{
    Delivery, Link, MeshEnvelope, MeshSim, RelayDecision, RelayNode, ResponderSink,
};
use aegismesh_core::scenario::{self, MeshConfig, SplitMix64};
use aegismesh_core::tap_classifier::{self, RhythmProfile};
use serde_json::{json, Value};

const SEED: u64 = 0xAE61_5EED;

fn rate(report: &scenario::Robustness, activity: &str) -> f64 {
    report
        .false_accepts
        .iter()
        .find(|f| f.activity == activity)
        .unwrap_or_else(|| panic!("no {activity} in {report:?}"))
        .rate
}

/// Per-frame motion energy as a webcam would see taps: noise plus a 4-frame bump per tap.
fn camera_signal(taps: &[f64], seconds: f64, fps: f64, seed: u64) -> Vec<MotionSample> {
    let mut rng = SplitMix64::new(seed);
    let frame_ms = 1000.0 / fps;
    (0..(seconds * fps) as usize)
        .map(|i| {
            let t = i as f64 * frame_ms;
            let mut energy = 0.8 + rng.unit() * 0.8;
            for &tap in taps {
                energy += match ((t - tap) / frame_ms).floor() as i64 {
                    0 => 6.0,
                    1 => 18.0,
                    2 => 14.0,
                    3 => 7.0,
                    _ => 0.0,
                };
            }
            MotionSample { t_ms: t, energy }
        })
        .collect()
}

fn sos_frame(secret: &[u8; KEY_LEN]) -> (Wearable, Vec<u8>) {
    let mut wearable = Wearable::new(FormFactor::Ring, secret, 0);
    let profile = wearable.profile().clone();
    let verdict = wearable.on_taps(
        &scenario::perform(&profile, 0.0),
        &SimulatedGnss::default(),
        1_700_000_000_000,
    );
    assert!(verdict.accepted, "{verdict:?}");
    let frame = wearable.tick(0).expect("first slot is due at start");
    assert!(!wearable.sos_pending());
    (wearable, frame)
}

// ------------------------------------------------------------- tap rhythm

#[test]
fn secret_rhythm_is_recognised_even_when_sloppy() {
    let profile = RhythmProfile::triple_tap();
    let verdict = tap_classifier::classify(&scenario::perform(&profile, 500.0), &profile);
    assert!(verdict.accepted, "{verdict:?}");
    assert!(verdict.confidence > 0.9, "{verdict:?}");

    let report = scenario::robustness(&profile, 2000, SEED);
    assert!(report.detection_rate >= 0.995, "{report:?}");
    assert!(report.sloppy_detection_rate >= 0.95, "{report:?}");
}

#[test]
fn walking_typing_and_stray_taps_are_rejected() {
    let profile = RhythmProfile::triple_tap();
    let report = scenario::robustness(&profile, 2000, SEED);
    for activity in ["walking", "strolling", "fidgeting"] {
        assert_eq!(rate(&report, activity), 0.0, "{activity}: {report:?}");
    }
    assert!(rate(&report, "typing") <= 0.004, "{report:?}");
    assert!(rate(&report, "random bumps") <= 0.02, "{report:?}");

    for case in scenario::tap_cases(&profile, 7) {
        assert!(case.pass, "{}: {:?}", case.name, case.verdict);
    }
}

#[test]
fn rejections_explain_themselves() {
    fn reason(taps: &[f64], profile: &RhythmProfile) -> String {
        tap_classifier::classify(taps, profile).reason
    }
    let profile = RhythmProfile::triple_tap();
    assert_eq!(reason(&[], &profile), "no taps");
    assert_eq!(
        reason(&[100.0, 5000.0, 9000.0], &profile),
        "single taps only"
    );
    let walking: Vec<f64> = (0..20).map(|i| f64::from(i) * 500.0).collect();
    assert!(reason(&walking, &profile).contains("continuous tapping"));
    let once = RhythmProfile {
        repeats: 1,
        ..profile.clone()
    };
    assert!(reason(&scenario::perform(&once, 2000.0), &profile).contains("perform it 2 times"));
    let mut crowded = scenario::perform(&profile, 2000.0);
    crowded.push(1500.0);
    crowded.push(1200.0);
    assert!(
        !tap_classifier::classify(&crowded, &profile).accepted,
        "taps right before the rhythm must block it"
    );
    let bounce = tap_classifier::clean_taps(&[100.0, 110.0, 400.0, f64::NAN]);
    assert_eq!(bounce, vec![100.0, 400.0]);
}

#[test]
fn calibration_learns_a_custom_rhythm() {
    let mut rng = SplitMix64::new(11);
    let samples: Vec<Vec<f64>> = (0..4)
        .map(|_| {
            let total = rng.range(700.0, 900.0);
            let mut t = 0.0;
            let mut sample = vec![0.0];
            for ratio in [0.2, 0.2, 0.6] {
                t += ratio * total * (1.0 + rng.range(-0.05, 0.05));
                sample.push(t);
            }
            sample
        })
        .collect();
    let profile = tap_classifier::calibrate(&samples, "knock-knock, pause, knock", 1).unwrap();
    assert_eq!(profile.taps(), 4);
    assert!((profile.ratios[2] - 0.6).abs() < 0.03, "{profile:?}");
    assert!(profile.validate().is_ok());
    let own = tap_classifier::classify(&scenario::perform(&profile, 0.0), &profile);
    assert!(own.accepted, "{own:?}");
    let triple = scenario::perform(&RhythmProfile::triple_tap(), 0.0);
    assert!(!tap_classifier::classify(&triple, &profile).accepted);

    let mut inconsistent = samples.clone();
    inconsistent[1] = vec![0.0, 480.0, 640.0, 800.0];
    assert!(tap_classifier::calibrate(&inconsistent, "x", 1).is_err());
    let mut wrong_count = samples.clone();
    wrong_count[2].pop();
    assert!(tap_classifier::calibrate(&wrong_count, "x", 1).is_err());
    assert!(tap_classifier::calibrate(&samples[..2], "x", 1).is_err());
}

// ------------------------------------------------------------- camera taps

#[test]
fn camera_motion_becomes_tap_times() {
    let profile = RhythmProfile::triple_tap();
    let taps = scenario::perform(&profile, 600.0);
    let report =
        camera_taps::detect_taps(&camera_signal(&taps, 6.0, 30.0, 3), &OnsetConfig::default());
    assert_eq!(report.taps_ms.len(), taps.len(), "{report:?}");
    for (found, real) in report.taps_ms.iter().zip(&taps) {
        assert!(
            (found - real).abs() <= 35.0,
            "tap at {real} found at {found}"
        );
    }
    assert!(
        (report.fps - 30.0).abs() < 1.0 && report.warning.is_none(),
        "{report:?}"
    );
    let verdict = tap_classifier::classify(&report.taps_ms, &profile);
    assert!(verdict.accepted, "{verdict:?}");

    let still =
        camera_taps::detect_taps(&camera_signal(&[], 5.0, 30.0, 4), &OnsetConfig::default());
    assert!(still.taps_ms.is_empty(), "{still:?}");
    let sway: Vec<MotionSample> = camera_signal(&[], 5.0, 30.0, 5)
        .into_iter()
        .enumerate()
        .map(|(i, s)| MotionSample {
            energy: s.energy + if (30..90).contains(&i) { 20.0 } else { 0.0 },
            ..s
        })
        .collect();
    assert!(
        camera_taps::detect_taps(&sway, &OnsetConfig::default())
            .taps_ms
            .len()
            <= 1
    );
    let slow =
        camera_taps::detect_taps(&camera_signal(&taps, 6.0, 8.0, 6), &OnsetConfig::default());
    assert!(slow.warning.is_some(), "{slow:?}");
}

// ------------------------------------------------------------- disguise

#[test]
fn distress_frame_is_disguised_as_fitness_telemetry() {
    let ratchet = KeyRatchet::from_pairing_secret(&[3u8; KEY_LEN]);
    let telemetry = Telemetry {
        sequence: 9,
        steps: 5_000,
        heart_rate: 70,
        battery: 80,
    };
    let fix = LocationFix {
        lat_e7: 515_007_123,
        lon_e7: -1_246_789,
        accuracy_m: 5,
        unix_ms: 1_700_000_000_000,
    };
    let token = ephemeral_crypto::distress_token(ratchet.current(), 0);
    let mut wellness_plain = [0u8; PLAINTEXT_LEN];
    disguise::write_wellness_plaintext(&mut wellness_plain);
    let mut distress_plain = [0u8; PLAINTEXT_LEN];
    disguise::write_distress_plaintext(&mut distress_plain, 0, &token, &fix);
    let wellness = disguise::encode_frame(&telemetry, &wellness_plain, ratchet.current());
    let distress = disguise::encode_frame(&telemetry, &distress_plain, ratchet.current());

    assert_eq!(wellness.len(), FRAME_LEN);
    assert_eq!(distress.len(), FRAME_LEN);
    assert_eq!(wellness[..HEADER_LEN], distress[..HEADER_LEN]);
    assert_eq!(disguise::parse_header(&distress), Some(telemetry.clone()));
    let lat = fix.lat_e7.to_le_bytes();
    assert!(
        !distress.windows(4).any(|w| w == lat),
        "location leaked in clear"
    );

    let sealed = disguise::extension(&distress).unwrap();
    match disguise::decode_extension(&sealed, ratchet.current()) {
        Some(Decoded::Distress {
            counter,
            token: got,
            fix: got_fix,
        }) => {
            assert_eq!(counter, 0);
            assert_eq!(got, token);
            assert_eq!(got_fix, fix);
        }
        other => panic!("expected a distress payload, got {other:?}"),
    }
    let wellness_sealed = disguise::extension(&wellness).unwrap();
    assert_eq!(
        disguise::decode_extension(&wellness_sealed, ratchet.current()),
        Some(Decoded::Wellness)
    );
    let stranger = KeyRatchet::from_pairing_secret(&[4u8; KEY_LEN]);
    assert_eq!(
        disguise::decode_extension(&sealed, stranger.current()),
        None
    );
    let mut tampered = sealed.clone();
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        disguise::decode_extension(&tampered, ratchet.current()),
        None
    );
}

#[test]
fn advertising_cadence_is_identical_with_and_without_sos() {
    let run = |sos_at: Option<u64>| -> (Vec<u64>, u32) {
        let mut wearable = Wearable::new(FormFactor::Bracelet, &[1u8; KEY_LEN], 0);
        let profile = wearable.profile().clone();
        let mut times = Vec::new();
        let mut now = 0u64;
        while now <= 8_000 {
            if Some(now) == sos_at {
                wearable.on_taps(
                    &scenario::perform(&profile, 0.0),
                    &SimulatedGnss::default(),
                    0,
                );
            }
            if wearable.tick(now).is_some() {
                times.push(now);
            }
            now += 10;
        }
        (times, wearable.sos_sent())
    };
    let (quiet, quiet_sos) = run(None);
    let (busy, busy_sos) = run(Some(3_330));
    assert_eq!(quiet, busy);
    assert_eq!((quiet_sos, busy_sos), (0, 1));
    assert!(quiet.windows(2).all(|w| w[1] - w[0] == 1_000), "{quiet:?}");
}

// ------------------------------------------------------------- mesh relay

#[test]
fn mesh_forwards_hop_by_hop_within_the_ttl() {
    let secret = [7u8; KEY_LEN];
    let (wearable, frame) = sos_frame(&secret);
    let line: Vec<Link> = (0..=3).map(|i| Link::new(i, i + 1)).collect();
    let run = |ttl: u8, links: Vec<Link>| {
        let mut sim = MeshSim::new(5, links, 4, ResponderSink::new(&secret));
        sim.inject(0, MeshEnvelope::from_frame(&frame, ttl).unwrap());
        let stats = sim.run(32).clone();
        (stats, sim.sink.alerts.clone(), sim.events.clone())
    };

    let (short, alerts, _) = run(3, line.clone());
    assert_eq!(short.delivered_sos, 0, "4 hops needed, TTL 3: {short:?}");
    assert_eq!(short.ttl_exhausted, 1);
    assert!(alerts.is_empty());

    let (enough, alerts, events) = run(4, line.clone());
    assert_eq!(enough.delivered_sos, 1, "{enough:?}");
    assert_eq!(enough.max_hops, 4);
    assert_eq!(
        alerts[0].fix,
        SimulatedGnss::default().fix(1_700_000_000_000)
    );
    let ttls: Vec<u8> = events.iter().map(|e| e.ttl).collect();
    assert_eq!(ttls, vec![3, 2, 1, 0], "TTL drops by one per hop");

    let mut meshed = line;
    meshed.extend((0..3).map(|i| Link::new(i, i + 2)));
    let (redundant, alerts, _) = run(4, meshed);
    assert_eq!(redundant.delivered_sos, 1, "{redundant:?}");
    assert_eq!(alerts.len(), 1);
    assert!(redundant.duplicates_dropped > 0, "{redundant:?}");
    assert!(wearable.phone_effects().is_silent());
}

#[test]
fn relay_drops_duplicates_and_spent_envelopes() {
    let (_, frame) = sos_frame(&[8u8; KEY_LEN]);
    let mut node = RelayNode::new(16);
    let fresh = MeshEnvelope::from_frame(&frame, 2).unwrap();
    assert_eq!(node.receive(&fresh), RelayDecision::Forward);
    assert_eq!(node.receive(&fresh), RelayDecision::Duplicate);
    let (_, other) = sos_frame(&[8u8; KEY_LEN]);
    let spent = MeshEnvelope::from_frame(&other, 0).unwrap();
    assert_eq!(node.receive(&spent), RelayDecision::Exhausted);
}

#[test]
fn end_to_end_mesh_scenario_is_silent_and_complete() {
    for form in FormFactor::ALL {
        let outcome = scenario::mesh_scenario(&MeshConfig {
            form,
            ..MeshConfig::default()
        });
        assert!(outcome.pass, "{form:?}: {:#?}", outcome.checks);
        assert_eq!(outcome.stats.delivered_sos, 1);
        assert!(outcome.stats.stored_then_forwarded > 0);
        assert!(outcome.phone.is_silent());
        assert_eq!(outcome.retained_location_bytes, 0);
        assert!(outcome.stats.wellness_discarded > 0);
    }
}

#[test]
fn camera_sign_triggers_the_same_silent_pipeline() {
    let outcome = scenario::mesh_scenario(&MeshConfig {
        camera_sign: Some("Signal for Help".to_string()),
        late_link: false,
        ..MeshConfig::default()
    });
    assert!(outcome.pass, "{:#?}", outcome.checks);
    assert_eq!(outcome.stats.delivered_sos, 1);
    assert!(
        outcome.tap.reason.contains("Signal for Help"),
        "{}",
        outcome.tap.reason
    );
    assert!(outcome.phone.is_silent());
    assert_eq!(outcome.retained_location_bytes, 0);

    let mut wearable = Wearable::new(FormFactor::Ring, &[4u8; KEY_LEN], 0);
    assert!(wearable.trigger_sos(&SimulatedGnss::default(), 0));
    assert!(
        !wearable.trigger_sos(&SimulatedGnss::default(), 0),
        "one SOS at a time"
    );
    assert!(wearable.tick(0).is_some() && !wearable.sos_pending());
}

#[test]
fn envelopes_carry_no_origin_or_destination() {
    let (_, a) = sos_frame(&[9u8; KEY_LEN]);
    let (_, b) = sos_frame(&[9u8; KEY_LEN]);
    let first = MeshEnvelope::from_frame(&a, 5).unwrap();
    let second = MeshEnvelope::from_frame(&b, 5).unwrap();
    assert_eq!(first.to_bytes().len(), 1 + EXTENSION_LEN);
    let mut fields: Vec<String> = serde_json::to_value(&first)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    fields.sort();
    assert_eq!(fields, ["sealed", "ttl"]);
    let same_bytes = first
        .to_bytes()
        .iter()
        .zip(second.to_bytes())
        .filter(|(x, y)| **x == *y)
        .count();
    assert!(
        same_bytes < 16,
        "identical SOS from the same device must be unlinkable ({same_bytes} equal bytes)"
    );
}

// ------------------------------------------------------------- zeroization

#[test]
fn buffers_are_wiped_immediately_after_dispatch() {
    let mut buffers = DispatchBuffers::new(LocationFix {
        lat_e7: 1,
        lon_e7: 2,
        accuracy_m: 3,
        unix_ms: 4,
    });
    buffers.token = [9u8; 16];
    buffers.plaintext = [7u8; PLAINTEXT_LEN];
    assert!(buffers.sensitive_bytes() > 0);
    let report = buffers.wipe();
    assert!(report.verified_zero, "{report:?}");
    assert_eq!(buffers.sensitive_bytes(), 0);
    assert!(buffers.fix.is_zero());
    assert_eq!(report.wiped_bytes, buffers.total_bytes());
    assert!(report.elapsed_ns < scenario::MAX_WIPE_NS);

    for form in FormFactor::ALL {
        let outcome = scenario::zeroization_scenario(form);
        assert!(outcome.pass, "{outcome:?}");
        assert!(outcome.held_before_dispatch > 0);
        assert_eq!(outcome.retained_location_bytes, 0);
    }
}

#[test]
fn seized_device_cannot_read_past_sos_and_replays_fail() {
    let secret = [5u8; KEY_LEN];
    let (wearable, frame) = sos_frame(&secret);
    let sealed = disguise::extension(&frame).unwrap();
    assert!(disguise::decode_extension(&sealed, &wearable.seized_key()).is_none());
    assert_eq!(wearable.epoch(), 1);

    let mut sink = ResponderSink::new(&secret);
    assert_eq!(sink.deliver(&sealed, 1), Delivery::Sos);
    assert_eq!(sink.deliver(&sealed, 1), Delivery::Rejected);
    assert_eq!(sink.alerts.len(), 1);
}

#[test]
fn late_frames_from_earlier_epochs_still_decode_at_the_responder() {
    let secret = [6u8; KEY_LEN];
    let mut wearable = Wearable::new(FormFactor::Ring, &secret, 0);
    let frames: Vec<Vec<u8>> = (0..20u64).filter_map(|i| wearable.tick(i * 1000)).collect();
    assert_eq!(frames.len(), 20);
    let mut sink = ResponderSink::new(&secret);
    for index in [17, 9, 1] {
        let sealed = disguise::extension(&frames[index]).unwrap();
        assert_eq!(
            sink.deliver(&sealed, 1),
            Delivery::Wellness,
            "frame {index}"
        );
    }
}

// ------------------------------------------------------------- anti-spyware

#[test]
fn nobody_can_pull_history_audio_beacons_or_keys() {
    let (mut wearable, _) = sos_frame(&[2u8; KEY_LEN]);
    for query in [
        ExternalQuery::LocationHistory,
        ExternalQuery::LastKnownLocation,
        ExternalQuery::StartAudioCapture,
        ExternalQuery::ForceBeacon { interval_ms: 20 },
        ExternalQuery::ExportKeys,
    ] {
        let response = wearable.handle_query(&query);
        assert!(
            matches!(response, QueryResponse::Denied { .. }),
            "{query:?} answered with {response:?}"
        );
    }
    assert_eq!(wearable.cadence_interval_ms(), 1_000);
    assert!(matches!(
        wearable.handle_query(&ExternalQuery::Status),
        QueryResponse::Status { .. }
    ));
    assert_eq!(wearable.retained_location_bytes(), 0);

    let audit = scenario::privacy_audit(FormFactor::ClothingTag);
    assert!(audit.len() >= 12);
    for check in &audit {
        assert!(check.passed, "{}: {}", check.name, check.detail);
    }
}

// ------------------------------------------------------------- console API

#[test]
fn console_api_round_trips() {
    let defaults = console::handle("defaults", &Value::Null).unwrap();
    assert_eq!(defaults["forms"].as_array().unwrap().len(), 3);
    assert_eq!(defaults["simulation_only"], true);

    let profile = RhythmProfile::triple_tap();
    let taps = scenario::perform(&profile, 400.0);
    let classified = console::handle(
        "classify",
        &json!({ "taps_ms": &taps, "profile": &profile }),
    )
    .unwrap();
    assert_eq!(classified["accepted"], true, "{classified}");

    let samples = camera_signal(&taps, 6.0, 30.0, 9);
    let camera = console::handle(
        "camera_detect",
        &json!({ "samples": &samples, "profile": &profile }),
    )
    .unwrap();
    assert_eq!(camera["verdict"]["accepted"], true, "{camera}");
    assert_eq!(camera["onsets"]["taps_ms"].as_array().unwrap().len(), 6);

    let mesh =
        console::handle("simulate_mesh", &json!({ "relays": 3, "form": "bracelet" })).unwrap();
    assert_eq!(mesh["pass"], true, "{mesh}");
    let signed = console::handle(
        "simulate_mesh",
        &json!({ "camera_sign": "Wink, then the other eye", "late_link": false }),
    )
    .unwrap();
    assert_eq!(signed["pass"], true, "{signed}");
    let bench = console::handle("robustness", &json!({ "trials": 200 })).unwrap();
    assert!(bench["detection_rate"].as_f64().unwrap() > 0.98, "{bench}");
    let preview = console::handle("frame_preview", &json!({ "form": "clothing_tag" })).unwrap();
    assert_eq!(preview["same_header_shape"], true);
    assert!(console::handle("does_not_exist", &Value::Null).is_err());
    assert!(console::handle("classify", &json!({ "taps_ms": "nope" })).is_err());
}
