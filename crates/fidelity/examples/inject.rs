//! Reports what the injection detector sees in this process.
//!
//! The example holds no hostile code, because the workspace forbids `unsafe`
//! outside a probe crate. The hostile control is external, and it is what an
//! injected agent really does: it maps executable memory that no file accounts
//! for. On Linux, preload a library whose constructor maps such a region:
//!
//! ```text
//! cargo run --example inject                       # clean control
//! LD_PRELOAD=./agent.so cargo run --example inject # hostile control
//! ```
//!
//! A library that a loader maps from a file does not trip this detector by
//! itself, by design. The plan records that coverage limit.

use fidelity::{Action, Outcome, SignalStrength};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new()
        .instrumentation(Action::Deny, SignalStrength::Medium)
        .start()?;

    for state in handle.snapshot().detectors() {
        let name = state.detector().name();
        match state.outcome() {
            Outcome::NotRun => println!("  {name}: no scan reached it"),
            Outcome::Clean => println!("  {name}: clean"),
            Outcome::Unsupported { reason } => println!("  {name}: unsupported, {reason}"),
            Outcome::Finding(finding) => println!(
                "  {name}: {:?}, {:?}",
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
