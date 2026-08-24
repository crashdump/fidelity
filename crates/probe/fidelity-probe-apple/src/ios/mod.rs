//! The iOS probe.
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that iOS does not answer yet gets an empty `impl` here, which
//! states the gap without a method body to read.
//!
//! iOS answers `tracer` and `baseline` with the kernel interfaces that macOS
//! uses, so both bodies live in [`common`](crate::common).
//!
//! iOS differs from macOS in two ways that matter here, and both live in
//! [`identity`](crate::ios::identity). The kernel enforces code signing and
//! exposes no equivalent of `SecCodeCheckValidity`, so platform trust reports
//! a gap rather than a verdict. Expected identity reads the team identifier
//! from the App ID prefix, out of the entitlements that the image carries.

mod baseline;
mod dispatch;
mod emulation;
mod identity;
mod lifecycle;
mod local_agent;
mod tracer;

use fidelity_core::{
    Baseline, Device, Dispatch, Emulation, Environment, Identity, ImageCatalog, Injection,
    Lifecycle, Tracer, VerifiedBoot,
};
use fidelity_types::Platform;

/// The iOS view of the running process.
///
/// The probe holds no operating-system handle between scans. It asks for a
/// reference each time, so a scan reads the current state rather than a value
/// that the probe cached at start.
#[derive(Debug)]
pub struct IosEnvironment;

impl IosEnvironment {
    /// Creates the iOS environment.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for IosEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for IosEnvironment {
    fn platform(&self) -> Platform {
        Platform::Ios
    }
}

// `Baseline`, `Identity`, and `Tracer` carry real platform code, so each one
// lives in the file of its own name. Every capability that iOS gains later
// follows that shape. Until it does, an empty `impl` here states the gap, and
// the trait default reports `Unsupported`.
const _: fn() = || {
    fn implements<T: Baseline + Dispatch + Emulation + Identity + Lifecycle + Tracer>() {}
    implements::<IosEnvironment>();
};

// iOS cannot answer `injection`, for the reason that the macOS probe states:
// a clean Apple process holds gigabytes of executable memory that no interface
// attributes, so no absolute rule separates an injected mapping from it. The
// runtime baseline answers the same question with a comparison instead.
impl Injection for IosEnvironment {}

impl ImageCatalog for IosEnvironment {}

// iOS offers no public state that separates a jailbreak from a released
// device. The iOS 26.5 SDK declares `kern.securelevel`, but a provisioned
// application on iOS 26.6.1 receives `EPERM` when it reads that value. A path
// list is excluded evidence, so the capability states the gap.
impl Device for IosEnvironment {}

impl VerifiedBoot for IosEnvironment {}

#[cfg(test)]
mod tests {
    use fidelity_core::Environment;
    use fidelity_types::Platform;

    use super::IosEnvironment;

    #[test]
    fn the_probe_reports_ios() {
        assert_eq!(IosEnvironment::new().platform(), Platform::Ios);
    }
}
