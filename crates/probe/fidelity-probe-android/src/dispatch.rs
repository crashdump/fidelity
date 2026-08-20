//! The dispatch capability on Android.
//!
//! Android reads the object that holds the code of Fidelity, and not the main
//! image. An application forks from zygote, so its main image is
//! `/system/bin/app_process64`, which every application on the device shares
//! and which no host controls. [`sys::dispatch`](crate::sys::dispatch) holds
//! the measurements that decide the rule.

use fidelity_core::{Dispatch, DispatchTargets, Observation, Target};

use crate::AndroidEnvironment;
use crate::sys;

impl Dispatch for AndroidEnvironment {
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

    use super::AndroidEnvironment;

    #[test]
    fn the_probe_reports_the_dispatch_targets_of_its_own_image() {
        // A test binary is one image, and the toolchain links it with a
        // jump-slot table, so the probe reports one. An application process
        // holds the same crate in a library instead, and the instrumented test
        // covers that case.
        let Observation::Fact(targets) = AndroidEnvironment::new().dispatch_targets() else {
            panic!("Android must report its dispatch targets");
        };
        assert!(!targets.targets().is_empty());
    }

    #[test]
    fn the_probe_reports_a_table_that_the_loader_bound_before_the_process_ran() {
        // The comparison needs a bound table, and a table that the loader
        // binds on the first call rewrites its own entries. The Android
        // toolchain links with full binding, and this states that it did.
        let Observation::Fact(targets) = AndroidEnvironment::new().dispatch_targets() else {
            panic!("Android must report its dispatch targets");
        };
        assert!(targets.is_bound());
    }

    #[test]
    fn two_reads_of_an_unchanged_table_report_no_redirect() {
        let environment = AndroidEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) = (
            environment.dispatch_targets(),
            environment.dispatch_targets(),
        ) else {
            panic!("Android must report its dispatch targets");
        };
        assert!(second.redirected_since(&first).is_empty());
    }

    #[test]
    fn the_image_that_the_probe_selects_is_the_one_that_runs_this_test() {
        // The selection rule, in the one case a shell binary can prove: this
        // crate sits in the test binary, so the probe must name that binary
        // and none of the seven other objects that the loader mapped.
        let (Some(found), Ok(running)) =
            (super::sys::dispatch::image_path(), std::env::current_exe())
        else {
            panic!("the probe and the process must both name an image");
        };
        assert_eq!(std::path::Path::new(&found), running);
    }
}
