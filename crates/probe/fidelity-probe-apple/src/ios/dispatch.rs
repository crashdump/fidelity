//! The dispatch capability on iOS.
//!
//! macOS reads the same table the same way, so the body lives in
//! [`common::dispatch`](crate::common::dispatch) and this file binds it to the
//! iOS environment.

use fidelity_core::{Dispatch, DispatchTargets, Observation};

use crate::common;

use super::IosEnvironment;

impl Dispatch for IosEnvironment {
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        common::dispatch::dispatch_targets()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Dispatch, Observation};

    use super::IosEnvironment;

    #[test]
    fn the_probe_reports_the_symbol_pointers_of_the_main_image() {
        let Observation::Fact(targets) = IosEnvironment::new().dispatch_targets() else {
            panic!("iOS must report its dispatch targets");
        };
        assert!(!targets.targets().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_table_report_no_redirect() {
        let environment = IosEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) = (
            environment.dispatch_targets(),
            environment.dispatch_targets(),
        ) else {
            panic!("iOS must report its dispatch targets");
        };
        assert!(second.redirected_since(&first).is_empty());
    }
}
