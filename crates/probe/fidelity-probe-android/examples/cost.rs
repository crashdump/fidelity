//! Measures what each capability read costs on Android.
//!
//! Run it in release mode, with the device runner that
//! [the test record](../../../../tests/platform/README.md) sets up:
//!
//! ```text
//! export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER=$PWD/tests/platform/controls/run-android.sh
//! cargo run --release --example cost -p fidelity-probe-android \
//!     --target aarch64-linux-android
//! ```
//!
//! The worker calls every read below on each cycle, so their sum is one cycle.
//! A shell binary maps no archive, so `code_identity` reports its gap quickly
//! there. An application process pays the archive read, and the instrumented
//! harness is what measures that.

/// The measurement loop, which the four probe examples share.
#[cfg(target_os = "android")]
#[path = "../../measure.rs"]
mod measure;

#[cfg(target_os = "android")]
fn main() {
    use std::hint::black_box;

    use fidelity_core::Environment;
    use fidelity_probe_android::AndroidEnvironment;
    use fidelity_types::{CertificateSha256, Choice, ExpectedIdentity};

    // The value matches no archive. A comparison costs the same either way,
    // because the archive read in front of it is the whole cost.
    let expected =
        ExpectedIdentity::new().android(Choice::Value(CertificateSha256::from_bytes([0; 32])));

    let probe = AndroidEnvironment::new();
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
    measure::report("code_origin", || {
        black_box(black_box(environment).code_origin());
    });
    measure::report("dispatch_targets", || {
        black_box(black_box(environment).dispatch_targets());
    });
    measure::report("system_build", || {
        black_box(black_box(environment).system_build());
    });
    measure::report("machine_host", || {
        black_box(black_box(environment).machine_host());
    });
}

#[cfg(not(target_os = "android"))]
fn main() {
    println!("this example measures Android only");
}
