//! The runtime baseline body that both Apple systems run.
//!
//! Both systems walk the top-level executable regions of the task through
//! Mach, so the body is here rather than in one system's module. The walk
//! itself, and the measurement that selected it, live in
//! [`sys::regions`](crate::sys::regions).

use fidelity_core::{CodeRegions, Observation, Region};
use fidelity_types::BoundedText;

use crate::sys::regions;

/// Reads the executable regions that the kernel reports for this task.
pub(crate) fn code_regions() -> Observation<CodeRegions> {
    match regions::executable() {
        Ok(found) => Observation::Fact(CodeRegions::new(
            found
                .into_iter()
                .map(|region| Region::new(region.start, region.end, region.writable))
                .collect(),
        )),
        Err(detail) => Observation::Failed {
            detail: BoundedText::new(detail),
        },
    }
}
