//! Reports what the tracer detector sees in this process.
//!
//! The clean control and the hostile control are the same binary. Run it
//! twice, and the second run under a debugger:
//!
//! ```text
//! cargo run --example tracer
//! lldb -b -o run -- target/debug/examples/tracer
//! ```
//!
//! The first run reports clean. The second reports a `Medium` finding, and it
//! denies the protected operation, because this example lowers the `Debugging`
//! threshold to `Medium` to show the action.

use fidelity::{Action, Outcome, SignalStrength};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new()
        .debugging(Action::Deny, SignalStrength::Medium)
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
