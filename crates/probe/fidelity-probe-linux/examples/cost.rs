//! Measures what each capability read costs on Linux.
//!
//! Run it in release mode, because that is what a host ships:
//!
//! ```text
//! cargo run --release --example cost -p fidelity-probe-linux
//! ```
//!
//! The worker calls every read below on each cycle, so their sum is one cycle.
//! `identity` is absent, because no Linux code answers it yet. See the
//! [coverage matrix](../../../../docs/plan/06-delivery.md#capability-coverage).

/// The measurement loop, which the three probe examples share.
#[cfg(target_os = "linux")]
#[path = "../../measure.rs"]
mod measure;

#[cfg(target_os = "linux")]
fn main() {
    use std::hint::black_box;

    use fidelity_core::Environment;
    use fidelity_probe_linux::LinuxEnvironment;

    let probe = LinuxEnvironment::new();
    let environment: &dyn Environment = &probe;
    println!("{}", measure::heading());
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

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("this example measures Linux only");
}
