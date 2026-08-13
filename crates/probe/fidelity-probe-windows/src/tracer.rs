//! The tracer capability on Windows.

use fidelity_core::{Observation, Tracer, TracerState};
use fidelity_types::BoundedText;

use crate::WindowsEnvironment;
use crate::sys;

/// What the evidence says when the kernel names a debugger.
///
/// The text names the mechanism and holds no application data. It states no
/// process identifier: the plan excludes a parent or a process name as
/// decisive evidence, and the identifier adds nothing that the finding needs.
const TRACED: &str = "the kernel reports a debugger on this process";

impl Tracer for WindowsEnvironment {
    fn tracer_state(&self) -> Observation<TracerState> {
        match sys::debug::debugger_present() {
            Ok(false) => Observation::Fact(TracerState::Absent),
            Ok(true) => Observation::Fact(TracerState::Present {
                detail: BoundedText::new(TRACED),
            }),
            Err(detail) => Observation::Failed {
                detail: BoundedText::new(detail),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Observation, Tracer, TracerState};

    use super::WindowsEnvironment;

    #[test]
    fn a_clean_process_reports_no_tracer() {
        // The clean control. The hostile control runs the example under a
        // debugger, because a test runner that a debugger holds cannot also
        // be the clean control.
        assert_eq!(
            WindowsEnvironment::new().tracer_state(),
            Observation::Fact(TracerState::Absent)
        );
    }
}
