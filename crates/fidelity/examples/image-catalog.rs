//! Reports whether the loader accounts for each executable file image.

use fidelity::{Action, Outcome, SignalStrength};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new()
        .instrumentation(Action::Deny, SignalStrength::Medium)
        .start()?;

    for state in handle.snapshot().detectors() {
        if state.detector().name() != "instrumentation.image_catalog" {
            continue;
        }
        match state.outcome() {
            Outcome::NotRun => println!("image catalog: no scan reached it"),
            Outcome::Clean => println!("image catalog: clean"),
            Outcome::Unsupported { reason } => println!("image catalog: unsupported, {reason}"),
            Outcome::Finding(finding) => println!(
                "image catalog: {:?}, {:?}",
                finding.strength(),
                finding.evidence()
            ),
        }
    }

    match handle.ensure_allowed() {
        Ok(()) => println!("protected operation: allowed"),
        Err(denial) => println!("protected operation: denied, {denial}"),
    }
    Ok(())
}
