//! The runtime baseline capability on iOS.
//!
//! macOS walks the same Mach interface, so the body lives in
//! [`common::baseline`](crate::common::baseline) and this file binds it to the
//! iOS environment.
//!
//! The two systems report different region counts, and the detector does not
//! depend on the count. Measured on 2026-08-09, a clean macOS process holds 1
//! top-level executable region and a clean iOS simulator process holds 8,
//! because the simulator runtime maps its own shared cache. The baseline
//! compares one snapshot against another, so a starting count changes nothing.

use fidelity_core::{Baseline, CodeRegions, Observation};

use crate::common;

use super::IosEnvironment;

impl Baseline for IosEnvironment {
    fn code_regions(&self) -> Observation<CodeRegions> {
        common::baseline::code_regions()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Baseline, Observation};

    use super::IosEnvironment;

    #[test]
    fn the_probe_reports_the_executable_regions_of_this_process() {
        let Observation::Fact(regions) = IosEnvironment::new().code_regions() else {
            panic!("iOS must report its regions");
        };
        assert!(!regions.regions().is_empty());
    }

    /// How many pairs of reads the test takes before it gives up.
    ///
    /// A test runner runs other tests on other threads, and one of them can map
    /// code between the two reads. The macOS file records the measurement that
    /// found it. A walk that really moved would never produce an agreeing pair.
    const ATTEMPTS: usize = 8;

    #[test]
    fn two_reads_of_an_unchanged_process_add_no_region() {
        // The property the detector depends on. A walk that returned a moving
        // answer would report a finding on every cycle.
        let environment = IosEnvironment::new();
        let agreed = (0..ATTEMPTS).any(|_| {
            let (Observation::Fact(first), Observation::Fact(second)) =
                (environment.code_regions(), environment.code_regions())
            else {
                panic!("iOS must report its regions");
            };
            second.added_since(&first).is_empty()
        });
        assert!(agreed, "no pair of reads agreed, so the walk itself moves");
    }
}
