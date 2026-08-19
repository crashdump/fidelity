//! Reports what the `UiAbuse` category does with a host report.
//!
//! The clean control and the hostile control are the same binary, and an
//! argument selects which one runs:
//!
//! ```text
//! cargo run --example interface            # the clean half, and it reports nothing
//! cargo run --example interface overlay    # the hostile half, and it denies
//! ```
//!
//! This category takes its input from the host, and every other category reads
//! the operating system. No interface states that another application draws
//! above this one, and the flag that states it arrives on a touch that a `View`
//! receives. A library holds no `View`, so the host reads it and reports it.
//! `docs/plan/04-detectors-and-platforms.md` holds the measurement.
//!
//! The example lowers the `UiAbuse` threshold to `Medium`, because the default
//! is `High` and a reported overlay is `Medium`. That is the whole point of the
//! threshold: a host that acts on this category says so.

use fidelity::{Action, Outcome, SignalStrength, UiObservation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new()
        .ui_abuse(Action::Deny, SignalStrength::Medium)
        .start()?;

    // The clean half stops here and reports nothing, because no host report
    // reached the runtime. The slot stays at `NotRun`, which states the absence
    // of a report and never a clean result.
    if std::env::args().nth(1).as_deref() == Some("overlay") {
        handle.report_ui_abuse(UiObservation::Overlay);
    }

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
