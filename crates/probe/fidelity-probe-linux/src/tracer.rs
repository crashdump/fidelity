//! The tracer capability on Linux.

use fidelity_core::{Observation, Tracer, TracerState};
use fidelity_types::BoundedText;

use crate::LinuxEnvironment;
use fidelity_formats::procfs::status::{TracerPid, tracer_pid};

use crate::sys;

/// What the evidence says when the kernel names a tracer.
///
/// The text names the mechanism and holds no application data. It states no
/// process identifier: the plan excludes a parent or a process name as
/// decisive evidence, and the identifier adds nothing that the finding needs.
const TRACED: &str = "the kernel reports a TracerPid on this process";

/// What the evidence says when the status text holds no readable field.
const UNREADABLE: &str = "the process status file named no readable TracerPid";

impl Tracer for LinuxEnvironment {
    fn tracer_state(&self) -> Observation<TracerState> {
        let text = match sys::status::read() {
            Ok(text) => text,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        match tracer_pid(&text) {
            Some(TracerPid::Absent) => Observation::Fact(TracerState::Absent),
            Some(TracerPid::Present(_)) => Observation::Fact(TracerState::Present {
                detail: BoundedText::new(TRACED),
            }),
            None => Observation::Failed {
                detail: BoundedText::new(UNREADABLE),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Observation, Tracer, TracerState};

    use super::LinuxEnvironment;

    #[test]
    fn a_clean_process_reports_no_tracer() {
        // The clean control. The hostile control runs the example under `gdb`,
        // because a test runner that traces itself cannot also be the clean
        // control.
        assert_eq!(
            LinuxEnvironment::new().tracer_state(),
            Observation::Fact(TracerState::Absent)
        );
    }
}
