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
mod identity;
mod lifecycle;
mod tracer;

use fidelity_core::{
    Baseline, Device, Dispatch, Emulation, Environment, Identity, Injection, Lifecycle, Tracer,
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
    fn implements<T: Baseline + Identity + Lifecycle + Tracer>() {}
    implements::<IosEnvironment>();
};

// iOS cannot answer `injection`, for the reason that the macOS probe states:
// a clean Apple process holds gigabytes of executable memory that no interface
// attributes, so no absolute rule separates an injected mapping from it. The
// runtime baseline answers the same question with a comparison instead.
impl Injection for IosEnvironment {}

// iOS can answer `device`, and no code exists yet. A jailbreak weakens
// the same kernel guarantees that this probe already reads for identity,
// so the mechanism is reachable. It waits for a control that produces a
// jailbroken system, because no measurement means no detector.
impl Device for IosEnvironment {}

// iOS can answer `emulation`, and no code exists yet. Apple ships no way to
// run iOS in a virtual machine, and a commercial service does exactly that and
// sells it to anybody who studies an application, so the question applies.
//
// The macOS reader stays macOS only, and a measurement decided that rather
// than caution. Measured on 2026-08-19 in an iOS 18.5 simulator: a process
// there reads the kernel of the Mac that hosts it, so `kern.hv_vmm_present`,
// `hw.machine`, and `hw.model` each report what the Mac reports and none of
// them describes the simulator. A probe that took that value would state a
// clean result about a system it never read.
//
// The simulator is reachable and a device is not, so any rule that separated
// the two would rest on what this project believes a device reports. It waits
// for a device, because no measurement means no detector.
impl Emulation for IosEnvironment {}

// iOS can answer `dispatch`, and no code exists yet. A hook that rewrites a
// lazy or non-lazy symbol pointer of the main image redirects a call, and the
// pointer table is bounded and readable, so the question applies. The
// gigabytes that stop `injection` do not apply here, because this reads one
// table rather than counting memory. It waits for a measurement of a clean
// Apple table. See `docs/plan/04-detectors-and-platforms.md`.
impl Dispatch for IosEnvironment {}

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
