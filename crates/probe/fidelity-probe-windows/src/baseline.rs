//! The runtime baseline capability on Windows.

use fidelity_core::{Baseline, CodeRegions, Observation, Region};
use fidelity_types::BoundedText;

use crate::WindowsEnvironment;
use crate::sys;

impl Baseline for WindowsEnvironment {
    fn code_regions(&self) -> Observation<CodeRegions> {
        let walked = match sys::memory::executable() {
            Ok(walked) => walked,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        // The walk states the protection, and the baseline keeps it. A region
        // that start() mapped as read and execute, and that is writable now,
        // keeps its first address, so the range alone would report nothing.
        let regions: Vec<Region> = walked
            .into_iter()
            .map(|region| Region::new(region.start, region.end, region.writable))
            .collect();

        Observation::Fact(CodeRegions::new(regions))
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Baseline, Observation};

    use super::WindowsEnvironment;

    #[test]
    fn the_probe_reports_the_executable_regions_of_this_process() {
        let Observation::Fact(regions) = WindowsEnvironment::new().code_regions() else {
            panic!("Windows must report its regions");
        };
        assert!(!regions.regions().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_process_add_no_region() {
        let environment = WindowsEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) =
            (environment.code_regions(), environment.code_regions())
        else {
            panic!("Windows must report its regions");
        };
        // The failure names what arrived. This test failed once in about
        // fourteen runs on 2026-08-15, and it did not fail again in twenty.
        // A message that states the address, the size, and the writable flag
        // tells the next reader what arrived. A library that loads between
        // the two reads is legitimate, and anything else is not.
        let added: Vec<String> = second
            .added_since(&first)
            .iter()
            .map(|region| {
                format!(
                    "{:#x}..{:#x}, {} bytes, writable {}",
                    region.start(),
                    region.end(),
                    region.bytes(),
                    region.is_writable()
                )
            })
            .collect();
        assert!(added.is_empty(), "a second read added {}", added.join("; "));
    }
}
