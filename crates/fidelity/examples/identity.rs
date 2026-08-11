//! Reports what the identity detectors see in this process.
//!
//! Run it with the code requirement that your own signing pipeline produces:
//!
//! ```text
//! cargo run --example identity -- 'anchor apple generic and \
//!     certificate leaf[subject.OU] = "YOURTEAMID"'
//! ```
//!
//! Sign the built binary with your distribution certificate, run it again, and
//! compare. That pair is the clean control and the hostile control for image
//! identity on one machine.

use fidelity::{Action, Choice, CodeRequirement, ExpectedIdentity, Outcome, SignalStrength};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = fidelity::new().integrity(Action::Deny, SignalStrength::Medium);

    if let Some(requirement) = std::env::args().nth(1) {
        println!("expected identity: {requirement}");
        builder = builder.expected_identity(
            ExpectedIdentity::new()
                .macos(Choice::Value(CodeRequirement::new(requirement)?))
                .ios(Choice::AcceptUnsupported)
                .windows(Choice::AcceptUnsupported)
                .android(Choice::AcceptUnsupported)
                .linux(Choice::AcceptUnsupported),
        );
    } else {
        println!("expected identity: none, so that check reports Unsupported");
    }

    let handle = builder.start()?;

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
