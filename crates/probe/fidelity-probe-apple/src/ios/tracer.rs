//! The tracer capability on iOS.
//!
//! macOS reads the same kernel state through the same interface, so the body
//! lives in [`common::tracer`](crate::common::tracer) and this file binds it
//! to the iOS environment.

use fidelity_core::{Observation, Tracer, TracerState};

use crate::common;

use super::IosEnvironment;

impl Tracer for IosEnvironment {
    fn tracer_state(&self) -> Observation<TracerState> {
        common::tracer::tracer_state()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Observation, Tracer, TracerState};

    use super::IosEnvironment;

    #[test]
    fn a_clean_process_reports_no_tracer() {
        // The clean control. The hostile control attaches a debugger to the
        // process, because a test runner that traces itself cannot also be the
        // clean control.
        assert_eq!(
            IosEnvironment::new().tracer_state(),
            Observation::Fact(TracerState::Absent)
        );
    }
}
