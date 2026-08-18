//! Measures what each capability read costs on Windows.
//!
//! Run it in release mode, because that is what a host ships:
//!
//! ```text
//! cargo run --release --example cost -p fidelity-probe-windows
//! ```
//!
//! The worker calls every read below on each cycle, so their sum is one cycle.
//! It reads the identity twice, because platform trust and expected identity
//! answer different questions. See the
//! [coverage matrix](../../../../docs/plan/06-delivery.md#capability-coverage).
//!
//! A `first` line is the first call to that read in this process, which is the
//! call `start()` pays.
//!
//! Two reads walk the same address space here, and `code_origin` also asks the
//! operating system to name a file for each mapped section it finds. That
//! second call is what separates a section a file backs from one the page file
//! backs, so the difference between the two numbers is what the exact answer
//! costs.

/// The measurement loop, which the four probe examples share.
#[cfg(target_os = "windows")]
#[path = "../../measure.rs"]
mod measure;

#[cfg(target_os = "windows")]
fn main() {
    use std::hint::black_box;

    use fidelity_core::Environment;
    use fidelity_probe_windows::WindowsEnvironment;
    use fidelity_types::{AuthenticodeThumbprint, Choice, ExpectedIdentity};

    // The value matches no image. A comparison costs the same either way,
    // because the read in front of it is the whole cost.
    let Ok(thumbprint) = AuthenticodeThumbprint::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    ) else {
        println!("the pinned value must parse");
        return;
    };
    let expected = ExpectedIdentity::new().windows(Choice::Value(thumbprint));

    let probe = WindowsEnvironment::new();
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
    measure::first("code_regions", || {
        black_box(black_box(environment).code_regions());
    });
    measure::report("tracer_state", || {
        black_box(black_box(environment).tracer_state());
    });
    measure::report("code_regions", || {
        black_box(black_box(environment).code_regions());
    });
    measure::report("code_origin", || {
        black_box(black_box(environment).code_origin());
    });
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("this example measures Windows only");
}
