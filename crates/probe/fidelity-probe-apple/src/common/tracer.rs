//! The tracer body that both Apple systems run.
//!
//! The kernel holds this state, so the capability reads it and adds nothing.
//! macOS and iOS both answer through `sysctl`, which is why the body is here
//! rather than in one system's module.

use fidelity_core::{Observation, TracerState};
use fidelity_types::BoundedText;

use crate::sys::process::{self, Verdict};

/// What the evidence says when the kernel reports a tracer.
///
/// The text names the mechanism and holds no application data.
const TRACED: &str = "the kernel reports P_TRACED on this process";

/// Reads what the kernel reports about a tracer on this process.
pub(crate) fn tracer_state() -> Observation<TracerState> {
    match process::traced() {
        Verdict::Absent => Observation::Fact(TracerState::Absent),
        Verdict::Present => Observation::Fact(TracerState::Present {
            detail: BoundedText::new(TRACED),
        }),
        Verdict::Failed(detail) => Observation::Failed {
            detail: BoundedText::new(detail),
        },
    }
}
