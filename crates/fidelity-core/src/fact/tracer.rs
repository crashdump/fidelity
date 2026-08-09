//! The facts that the tracer capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about a tracer on this process.
///
/// The capability answers one question: does a debugger or a tracer hold this
/// process now? The engine keeps the strongest observation, so a tracer that
/// attaches once and detaches stays in the report. That is what lets the
/// `Debugging` category ask whether a tracer has interacted with the process,
/// and not only whether one holds it at this moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerState {
    /// No tracer holds the process.
    Absent,

    /// A tracer holds the process.
    Present {
        /// What the operating system reported, in text that holds no
        /// application data.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::TracerState;

    #[test]
    fn a_present_tracer_keeps_its_detail() {
        let state = TracerState::Present {
            detail: BoundedText::new("the kernel reports P_TRACED"),
        };
        assert_eq!(
            state,
            TracerState::Present {
                detail: BoundedText::new("the kernel reports P_TRACED"),
            }
        );
    }

    #[test]
    fn an_absent_tracer_differs_from_a_present_one() {
        assert_ne!(
            TracerState::Absent,
            TracerState::Present {
                detail: BoundedText::new("the kernel reports P_TRACED"),
            }
        );
    }
}
