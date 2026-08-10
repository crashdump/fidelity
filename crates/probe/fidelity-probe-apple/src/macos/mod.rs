//! The macOS probe.
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that macOS does not answer yet gets an empty `impl` here,
//! which states the gap without a method body to read.

mod baseline;
mod identity;
mod lifecycle;
mod tracer;

use fidelity_core::{Baseline, Device, Environment, Identity, Injection, Lifecycle, Tracer};
use fidelity_types::Platform;

/// The macOS view of the running process.
///
/// The probe holds no operating-system handle between scans. It asks for a
/// reference each time, so a scan reads the current state rather than a value
/// that the probe cached at start.
#[derive(Debug)]
pub struct MacEnvironment;

impl MacEnvironment {
    /// Creates the macOS environment.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MacEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for MacEnvironment {
    fn platform(&self) -> Platform {
        Platform::MacOs
    }
}

// `Identity` and `Tracer` carry real platform code, so each one lives in the
// file of its own name. Every capability that macOS gains later follows that
// shape. Until it does, an empty `impl` here states the gap, and the trait
// default reports `Unsupported`.
const _: fn() = || {
    fn implements<T: Baseline + Identity + Lifecycle + Tracer>() {}
    implements::<MacEnvironment>();
};

// macOS cannot answer `injection`, and the reason is measured rather than
// assumed. A clean process holds about 3.6 GB of executable memory that
// neither `proc_regionfilename` nor `dladdr` attributes, so an injected
// mapping is one more entry in a list that is already unattributed. The
// runtime baseline answers the same question with a comparison instead. See
// `docs/plan/04-detectors-and-platforms.md`.
impl Injection for MacEnvironment {}

// macOS cannot answer `device`. The category reports the loss of a privilege
// boundary that the operating system holds against its own user, and macOS
// grants that user administrator rights by design. There is no such boundary
// to lose, so the question does not apply rather than waiting for code.
impl Device for MacEnvironment {}

#[cfg(test)]
mod tests {
    use fidelity_core::Environment;
    use fidelity_types::Platform;

    use super::MacEnvironment;

    #[test]
    fn the_probe_reports_macos() {
        assert_eq!(MacEnvironment::new().platform(), Platform::MacOs);
    }
}
