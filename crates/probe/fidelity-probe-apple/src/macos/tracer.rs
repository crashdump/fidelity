//! The tracer capability on macOS.
//!
//! iOS reads the same kernel state through the same interface, so the body
//! lives in [`common::tracer`](crate::common::tracer) and this file binds it
//! to the macOS environment.

use fidelity_core::{Observation, Tracer, TracerState};

use crate::common;

use super::MacEnvironment;

impl Tracer for MacEnvironment {
    fn tracer_state(&self) -> Observation<TracerState> {
        common::tracer::tracer_state()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Observation, Tracer, TracerState};

    use super::MacEnvironment;

    #[test]
    fn a_clean_process_reports_no_tracer() {
        // The clean control. The hostile control runs under a real debugger,
        // in `crates/fidelity/examples/tracer.rs`, because a test runner that
        // attaches a debugger to itself cannot also be the clean control.
        assert_eq!(
            MacEnvironment::new().tracer_state(),
            Observation::Fact(TracerState::Absent)
        );
    }
}
