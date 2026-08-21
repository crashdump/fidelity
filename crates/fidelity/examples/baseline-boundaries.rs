//! Checks the writable-code and snapshot-limit baseline boundaries.
//!
//! An external control creates the memory subject before this process starts.
//! The `writable` mode expects `CodeMadeWritable` after the control adds write
//! access. The `limit` mode expects an initial `Unsupported` outcome.

use std::time::{Duration, Instant};

use fidelity::{Evidence, Handle, Outcome, SignalStrength};

/// The most time that the writable-code control waits.
const DEADLINE: Duration = Duration::from_secs(40);

/// The delay between two snapshot reads.
const POLL: Duration = Duration::from_millis(250);

/// The detector that this control reads.
const BASELINE: &str = "integrity.runtime_baseline";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mode) = std::env::args().nth(1) else {
        return Err("usage: baseline-boundaries <writable or limit>".into());
    };
    let handle = fidelity::new().start()?;

    match mode.as_str() {
        "writable" => wait_for_writable_code(&handle).map_err(Into::into),
        "limit" => require_limit(&handle).map_err(Into::into),
        _ => Err(format!("unknown baseline boundary: {mode}").into()),
    }
}

/// Waits for the control to add write access to executable code.
fn wait_for_writable_code(handle: &Handle) -> Result<(), String> {
    let began = Instant::now();
    while began.elapsed() < DEADLINE {
        if observes_writable_code(handle)? {
            println!("baseline reported CodeMadeWritable at Medium");
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    Err(String::from(
        "the baseline reported no writable code before the deadline",
    ))
}

/// Reports whether the baseline holds the required writable-code finding.
fn observes_writable_code(handle: &Handle) -> Result<bool, String> {
    let snapshot = handle.snapshot();
    let Some(state) = snapshot
        .detectors()
        .iter()
        .find(|state| state.detector().name() == BASELINE)
    else {
        return Err(String::from("the baseline detector is absent"));
    };

    match state.outcome() {
        Outcome::NotRun | Outcome::Clean => Ok(false),
        Outcome::Unsupported { reason } => Err(format!("the baseline is unsupported: {reason}")),
        Outcome::Finding(finding)
            if finding.strength() == SignalStrength::Medium
                && matches!(finding.evidence(), Evidence::CodeMadeWritable { .. }) =>
        {
            Ok(true)
        }
        Outcome::Finding(finding) => Err(format!(
            "the baseline reported another result: {:?}, {:?}",
            finding.strength(),
            finding.evidence()
        )),
    }
}

/// Requires an initial outcome that states the snapshot limit.
fn require_limit(handle: &Handle) -> Result<(), String> {
    let snapshot = handle.snapshot();
    let Some(state) = snapshot
        .detectors()
        .iter()
        .find(|state| state.detector().name() == BASELINE)
    else {
        return Err(String::from("the baseline detector is absent"));
    };

    match state.outcome() {
        Outcome::Unsupported { reason }
            if reason.contains("more executable regions than a snapshot keeps") =>
        {
            println!("baseline reported Unsupported above 1024 regions");
            Ok(())
        }
        outcome => Err(format!(
            "the baseline did not report the snapshot limit: {outcome:?}"
        )),
    }
}
