//! One JSON entry point for both desktop consoles (`op` plus `args`), so the Tauri layers stay
//! one line long and identical.

use crate::camera_taps::{self, MotionSample, OnsetConfig};
use crate::device::FormFactor;
use crate::scenario::{self, MeshConfig};
use crate::tap_classifier::{self, RhythmProfile};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T, String> {
    let args = if args.is_null() {
        Value::Object(Default::default())
    } else {
        args.clone()
    };
    serde_json::from_value(args).map_err(|e| format!("bad arguments: {e}"))
}

fn to_json<T: Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClassifyRequest {
    taps_ms: Vec<f64>,
    profile: RhythmProfile,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct CalibrateRequest {
    samples: Vec<Vec<f64>>,
    name: String,
    repeats: u32,
}

impl Default for CalibrateRequest {
    fn default() -> Self {
        Self {
            samples: Vec::new(),
            name: String::new(),
            repeats: 2,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CameraRequest {
    samples: Vec<MotionSample>,
    profile: RhythmProfile,
    onset: OnsetConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RobustnessRequest {
    profile: RhythmProfile,
    trials: usize,
    seed: u64,
}

impl Default for RobustnessRequest {
    fn default() -> Self {
        Self {
            profile: RhythmProfile::triple_tap(),
            trials: 1000,
            seed: 0xAE61_5EED,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct FormRequest {
    form: FormFactor,
}

impl Default for FormRequest {
    fn default() -> Self {
        Self {
            form: FormFactor::Ring,
        }
    }
}

pub fn handle(op: &str, args: &Value) -> Result<Value, String> {
    match op {
        "defaults" => Ok(json!({
            "forms": FormFactor::ALL.iter().map(|f| f.spec()).collect::<Vec<_>>(),
            "profiles": FormFactor::ALL.map(FormFactor::default_profile),
            "onset": OnsetConfig::default(),
            "simulation_only": true,
        })),
        "classify" => {
            let req: ClassifyRequest = parse(args)?;
            to_json(&tap_classifier::classify(&req.taps_ms, &req.profile))
        }
        "calibrate" => {
            let req: CalibrateRequest = parse(args)?;
            to_json(&tap_classifier::calibrate(
                &req.samples,
                &req.name,
                req.repeats,
            )?)
        }
        "camera_detect" => {
            let req: CameraRequest = parse(args)?;
            let onsets = camera_taps::detect_taps(&req.samples, &req.onset);
            let verdict = tap_classifier::classify(&onsets.taps_ms, &req.profile);
            Ok(json!({ "onsets": onsets, "verdict": verdict }))
        }
        "robustness" => {
            let req: RobustnessRequest = parse(args)?;
            req.profile.validate()?;
            to_json(&scenario::robustness(&req.profile, req.trials, req.seed))
        }
        "tap_cases" => {
            let req: ClassifyRequest = parse(args)?;
            req.profile.validate()?;
            to_json(&scenario::tap_cases(&req.profile, 7))
        }
        "simulate_mesh" => {
            let cfg: MeshConfig = parse(args)?;
            to_json(&scenario::mesh_scenario(&cfg))
        }
        "zeroization" => {
            let req: FormRequest = parse(args)?;
            to_json(&scenario::zeroization_scenario(req.form))
        }
        "privacy_audit" => {
            let req: FormRequest = parse(args)?;
            to_json(&scenario::privacy_audit(req.form))
        }
        "frame_preview" => {
            let req: FormRequest = parse(args)?;
            to_json(&scenario::frame_preview(req.form))
        }
        other => Err(format!("unknown AegisMesh operation: {other}")),
    }
}
