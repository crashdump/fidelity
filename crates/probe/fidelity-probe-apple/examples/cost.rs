//! Measures what each capability read costs on macOS and on iOS.
//!
//! Run it in release mode, because that is what a host ships:
//!
//! ```text
//! cargo run --release --example cost -p fidelity-probe-apple
//! ```
//!
//! The worker calls every read below on each cycle, so their sum is one cycle.
//! `injection` is absent, because Apple answers it through the runtime
//! baseline instead. See
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md).

/// The measurement loop, which the four probe examples share.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "../../measure.rs"]
mod measure;

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() {
    use std::hint::black_box;

    use fidelity_core::Environment;
    use fidelity_types::{Choice, CodeRequirement, ExpectedIdentity, TeamIdentifier};

    #[cfg(target_os = "ios")]
    use fidelity_probe_apple::IosEnvironment as Probe;
    #[cfg(target_os = "macos")]
    use fidelity_probe_apple::MacEnvironment as Probe;

    // Neither value matches this image. A comparison costs the same either
    // way, because the read in front of it is the whole cost.
    let (Ok(requirement), Ok(team)) = (
        CodeRequirement::new("anchor apple generic"),
        TeamIdentifier::new("ABCDE12345"),
    ) else {
        println!("the pinned values must parse");
        return;
    };
    let expected = ExpectedIdentity::new()
        .macos(Choice::Value(requirement))
        .ios(Choice::Value(team));

    let probe = Probe::new();
    let environment: &dyn Environment = &probe;
    println!("{}", measure::heading());
    measure::first("code_identity", || {
        black_box(black_box(environment).code_identity());
    });
    measure::report("code_identity", || {
        black_box(black_box(environment).code_identity());
    });
    measure::report("identity_match", || {
        black_box(black_box(environment).identity_match(&expected));
    });
    measure::report("tracer_state", || {
        black_box(black_box(environment).tracer_state());
    });
    measure::report("code_regions", || {
        black_box(black_box(environment).code_regions());
    });
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    println!("this example measures macOS and iOS only");
}
