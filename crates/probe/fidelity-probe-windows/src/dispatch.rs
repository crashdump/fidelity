//! The dispatch capability on Windows.

use fidelity_core::{Dispatch, DispatchTargets, Observation, Target};

use crate::WindowsEnvironment;
use crate::sys;

impl Dispatch for WindowsEnvironment {
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        let Some(raw) = sys::dispatch::read_targets() else {
            // A static image with no import table holds no dispatch target to
            // watch. That is a gap in coverage, and never a finding.
            return Observation::Unsupported {
                reason: "the main module holds no import table",
            };
        };

        let targets = raw
            .targets
            .into_iter()
            .map(|target| Target::new(target.slot, target.value))
            .collect();
        Observation::Fact(DispatchTargets::new(targets, raw.bound))
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Dispatch, Observation};

    use super::WindowsEnvironment;

    #[test]
    fn the_probe_reports_the_import_targets_of_the_main_module() {
        // The test binary is the main module, and the toolchain links it with
        // an import table, so the probe reports one.
        let Observation::Fact(targets) = WindowsEnvironment::new().dispatch_targets() else {
            panic!("Windows must report its dispatch targets");
        };
        assert!(!targets.targets().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_table_report_no_redirect() {
        let environment = WindowsEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) = (
            environment.dispatch_targets(),
            environment.dispatch_targets(),
        ) else {
            panic!("Windows must report its dispatch targets");
        };
        assert!(second.redirected_since(&first).is_empty());
    }
}
