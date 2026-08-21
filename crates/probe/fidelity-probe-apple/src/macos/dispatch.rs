//! The dispatch capability on macOS.
//!
//! iOS reads the same table the same way, so the body lives in
//! [`common::dispatch`] and this file binds it to the
//! macOS environment.

use fidelity_core::{Dispatch, DispatchTargets, Observation};

use crate::common;

use super::MacEnvironment;

impl Dispatch for MacEnvironment {
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        common::dispatch::dispatch_targets()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Dispatch, Observation};

    use super::MacEnvironment;

    #[test]
    fn the_probe_reports_the_symbol_pointers_of_the_main_image() {
        // The test binary is the main image, and every Apple toolchain writes
        // at least one non-lazy symbol-pointer section, so the probe reports
        // one. Whether the loader bound the table is a separate answer, and
        // the detector reads it.
        let Observation::Fact(targets) = MacEnvironment::new().dispatch_targets() else {
            panic!("macOS must report its dispatch targets");
        };
        assert!(!targets.targets().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_table_report_no_redirect() {
        let environment = MacEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) = (
            environment.dispatch_targets(),
            environment.dispatch_targets(),
        ) else {
            panic!("macOS must report its dispatch targets");
        };
        assert!(second.redirected_since(&first).is_empty());
    }
}
