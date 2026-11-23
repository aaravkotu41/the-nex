use aegismesh_core::device::FormFactor;
use aegismesh_core::scenario::{self, MeshConfig};
use serde_json::{json, Value};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: aegismesh-sim [SCENARIOS] [OPTIONS]

Scenarios (all of them when none is given):
  --simulate-tap         recognise the secret tap rhythm; reject walking, typing and fidgeting
  --simulate-mesh        silent SOS relayed hop by hop to the simulated responder
  --verify-zeroization   location and session buffers wiped right after dispatch
  --privacy-audit        anti-spyware and metadata checks
  --benchmark            Monte-Carlo detection and false-trigger rates

Options:
  --json-logs            print one JSON object per scenario
  --form <FORM>          ring (default), bracelet or clothing-tag
  --relays <N>           relays between wearable and responder, 1-12 (default 4)
  --ttl <N>              hop limit, 1-16 (default 6)
  --help                 show this help

Everything runs in memory: no radio, network, file or emergency service is used.
";

const ALL: [&str; 5] = [
    "simulate-tap",
    "simulate-mesh",
    "verify-zeroization",
    "privacy-audit",
    "benchmark",
];
const BENCHMARK_SEED: u64 = 0xAE61_5EED;

struct Options {
    scenarios: Vec<&'static str>,
    json: bool,
    form: FormFactor,
    relays: usize,
    ttl: u8,
}

fn value<I: Iterator<Item = String>>(args: &mut I, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|v| !v.starts_with("--"))
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse<I: Iterator<Item = String>>(mut args: I) -> Result<Option<Options>, String> {
    let mut opts = Options {
        scenarios: Vec::new(),
        json: false,
        form: FormFactor::Ring,
        relays: 4,
        ttl: 6,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--simulate-tap" => opts.scenarios.push(ALL[0]),
            "--simulate-mesh" => opts.scenarios.push(ALL[1]),
            "--verify-zeroization" => opts.scenarios.push(ALL[2]),
            "--privacy-audit" => opts.scenarios.push(ALL[3]),
            "--benchmark" => opts.scenarios.push(ALL[4]),
            "--all" => opts.scenarios.extend(ALL),
            "--json-logs" => opts.json = true,
            "--form" => {
                let name = value(&mut args, "--form")?;
                opts.form = FormFactor::parse(&name)
                    .ok_or_else(|| format!("unknown form factor: {name}"))?;
            }
            "--relays" => {
                opts.relays = value(&mut args, "--relays")?
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=12).contains(n))
                    .ok_or("--relays expects a number from 1 to 12")?;
            }
            "--ttl" => {
                opts.ttl = value(&mut args, "--ttl")?
                    .parse::<u8>()
                    .ok()
                    .filter(|n| (1..=16).contains(n))
                    .ok_or("--ttl expects a number from 1 to 16")?;
            }
            "--help" | "-h" => return Ok(None),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if opts.scenarios.is_empty() {
        opts.scenarios.extend(ALL);
    }
    let mut seen: Vec<&str> = Vec::new();
    opts.scenarios.retain(|name| {
        if seen.contains(name) {
            false
        } else {
            seen.push(*name);
            true
        }
    });
    Ok(Some(opts))
}

fn run(name: &str, opts: &Options) -> (bool, String, Value) {
    let profile = opts.form.default_profile();
    match name {
        "simulate-tap" => {
            let cases = scenario::tap_cases(&profile, 7);
            let passed = cases.iter().filter(|c| c.pass).count();
            let detail: Vec<Value> = cases
                .iter()
                .map(|c| {
                    json!({
                        "case": c.name,
                        "expect_accept": c.expect_accept,
                        "accepted": c.verdict.accepted,
                        "reason": c.verdict.reason,
                    })
                })
                .collect();
            (
                passed == cases.len(),
                format!(
                    "{passed}/{} cases as expected (secret rhythm accepted; walking, typing and fidgeting rejected)",
                    cases.len()
                ),
                Value::Array(detail),
            )
        }
        "simulate-mesh" => {
            let outcome = scenario::mesh_scenario(&MeshConfig {
                form: opts.form,
                relays: opts.relays,
                ttl: opts.ttl,
                ..MeshConfig::default()
            });
            let summary = format!(
                "SOS delivered {}x in {} hop(s) across {} relays; {} duplicates dropped; {} stored-and-forwarded; phone effects: {}",
                outcome.stats.delivered_sos,
                outcome.stats.max_hops,
                outcome.config.relays,
                outcome.stats.duplicates_dropped,
                outcome.stats.stored_then_forwarded,
                if outcome.phone.is_silent() { "none" } else { "PRESENT" }
            );
            let detail = json!({
                "checks": outcome.checks,
                "stats": outcome.stats,
                "phone": outcome.phone,
                "frames_sent": outcome.frames_sent,
                "hop_events": outcome.events.len(),
            });
            (outcome.pass, summary, detail)
        }
        "verify-zeroization" => {
            let outcome = scenario::zeroization_scenario(opts.form);
            let summary = match &outcome.wipe {
                Some(wipe) => format!(
                    "{} bytes wiped {:.1} us after dispatch, verified zero: {}; {} bytes retained",
                    wipe.wiped_bytes,
                    wipe.elapsed_ns as f64 / 1000.0,
                    wipe.verified_zero,
                    outcome.retained_location_bytes
                ),
                None => "no SOS was dispatched".to_string(),
            };
            (outcome.pass, summary, json!(outcome))
        }
        "privacy-audit" => {
            let checks = scenario::privacy_audit(opts.form);
            let passed = checks.iter().filter(|c| c.passed).count();
            (
                passed == checks.len(),
                format!(
                    "{passed}/{} privacy and anti-spyware checks passed",
                    checks.len()
                ),
                json!(checks),
            )
        }
        "benchmark" => {
            let report = scenario::robustness(&profile, 2000, BENCHMARK_SEED);
            let pass = report.detection_rate >= 0.99
                && report
                    .false_accepts
                    .iter()
                    .all(|f| match f.activity.as_str() {
                        "typing" => f.rate <= 0.004,
                        "random bumps" => f.rate <= 0.02,
                        _ => f.false_accepts == 0,
                    });
            let worst = report
                .false_accepts
                .iter()
                .map(|f| f.per_hour)
                .fold(0.0, f64::max);
            (
                pass,
                format!(
                    "{:.1}% of attempts recognised ({:.1}% when sloppy); worst false-trigger rate {worst:.2} per hour",
                    report.detection_rate * 100.0,
                    report.sloppy_detection_rate * 100.0
                ),
                json!(report),
            )
        }
        other => (false, format!("unknown scenario {other}"), Value::Null),
    }
}

fn main() -> ExitCode {
    let args = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned());
    let opts = match parse(args) {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut all_pass = true;
    for &name in &opts.scenarios {
        let (pass, summary, detail) = run(name, &opts);
        all_pass &= pass;
        if opts.json {
            let line = json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "scenario": name,
                "form": opts.form,
                "pass": pass,
                "summary": summary,
                "detail": detail,
            });
            println!("{line}");
        } else {
            let status = if pass { "PASS" } else { "FAIL" };
            println!("[{status}] {name:<20} {summary}");
        }
    }
    if all_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
