//! The runtime baseline capability on macOS.
//!
//! iOS walks the same Mach interface, so the body lives in
//! [`common::baseline`](crate::common::baseline) and this file binds it to the
//! macOS environment.

use fidelity_core::{Baseline, CodeRegions, Observation};

use crate::common;

use super::MacEnvironment;

impl Baseline for MacEnvironment {
    fn code_regions(&self) -> Observation<CodeRegions> {
        common::baseline::code_regions()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Baseline, Observation};

    use super::MacEnvironment;

    #[test]
    fn the_probe_reports_the_executable_regions_of_this_process() {
        let Observation::Fact(regions) = MacEnvironment::new().code_regions() else {
            panic!("macOS must report its regions");
        };
        assert!(!regions.regions().is_empty());
    }

    /// How many pairs of reads the test takes before it gives up.
    ///
    /// The property needs a quiet pair, and a test runner is not quiet: it runs
    /// other tests on other threads, and one of them can map code between the
    /// two reads. Measured under the address sanitizer on 2026-08-09, a
    /// concurrent test mapped 112 KiB while this one ran, and the single
    /// assertion below passed only by luck until then.
    ///
    /// A walk that really moved would never produce an agreeing pair, so the
    /// bound still fails a broken walk.
    const ATTEMPTS: usize = 8;

    #[test]
    fn two_reads_of_an_unchanged_process_add_no_region() {
        // The property the detector depends on. A walk that returned a moving
        // answer would report a finding on every cycle.
        let environment = MacEnvironment::new();
        let agreed = (0..ATTEMPTS).any(|_| {
            let (Observation::Fact(first), Observation::Fact(second)) =
                (environment.code_regions(), environment.code_regions())
            else {
                panic!("macOS must report its regions");
            };
            second.added_since(&first).is_empty()
        });
        assert!(agreed, "no pair of reads agreed, so the walk itself moves");
    }
}
