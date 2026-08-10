//! The runtime baseline capability on Linux.

use fidelity_core::{Baseline, CodeRegions, Observation, Region};
use fidelity_formats::procfs::maps;
use fidelity_types::BoundedText;

use crate::LinuxEnvironment;
use crate::sys;

impl Baseline for LinuxEnvironment {
    fn code_regions(&self) -> Observation<CodeRegions> {
        let text = match sys::maps::read() {
            Ok(text) => text,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        let regions: Vec<Region> = maps::executable_ranges(&text)
            .into_iter()
            .map(|(start, end)| Region::new(start, end))
            .collect();

        if regions.is_empty() {
            return Observation::Failed {
                detail: BoundedText::new("the mapping table named no executable region"),
            };
        }
        Observation::Fact(CodeRegions::new(regions))
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Baseline, Observation};

    use super::LinuxEnvironment;

    #[test]
    fn the_probe_reports_the_executable_regions_of_this_process() {
        let Observation::Fact(regions) = LinuxEnvironment::new().code_regions() else {
            panic!("Linux must report its regions");
        };
        assert!(!regions.regions().is_empty());
    }

    #[test]
    fn two_reads_of_an_unchanged_process_add_no_region() {
        let environment = LinuxEnvironment::new();
        let (Observation::Fact(first), Observation::Fact(second)) =
            (environment.code_regions(), environment.code_regions())
        else {
            panic!("Linux must report its regions");
        };
        assert!(second.added_since(&first).is_empty());
    }
}
