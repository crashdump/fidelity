//! The dispatch capability on Linux.

use fidelity_core::{Dispatch, DispatchTargets, Observation, Target};

use crate::LinuxEnvironment;
use crate::sys;

impl Dispatch for LinuxEnvironment {
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        let Some(raw) = sys::dispatch::read() else {
            // A static image, or an image with no jump-slot table, holds no
            // dispatch target to watch. That is a gap in coverage, and never a
            // finding.
            return Observation::Unsupported {
                reason: "the image of the host holds no dispatch table",
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

    use super::LinuxEnvironment;

    #[test]
    fn the_probe_reports_the_dispatch_targets_of_the_main_image() {
        // The test binary is the main image, and the toolchain links it with a
        // jump-slot table, so the probe reports one.
        let Observation::Fact(targets) = LinuxEnvironment::new().dispatch_targets() else {
            panic!("Linux must report its dispatch targets");
        };
        assert!(!targets.targets().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_table_report_no_redirect() {
        let environment = LinuxEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) = (
            environment.dispatch_targets(),
            environment.dispatch_targets(),
        ) else {
            panic!("Linux must report its dispatch targets");
        };
        assert!(second.redirected_since(&first).is_empty());
    }
}
