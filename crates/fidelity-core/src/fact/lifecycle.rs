//! What a platform needs from the worker thread.

use fidelity_types::BoundedText;

/// What a platform did to prepare the worker thread.
///
/// This is not an [`Observation`](crate::Observation), and the difference is
/// deliberate. Every other capability describes the environment, so a detector
/// turns its answer into a finding. This one describes what Fidelity did to
/// itself, so nothing routes it to a category and no strength applies.
///
/// A failure here degrades the worker, and it never stops it. A worker that
/// refused to run because it could not lower its own scheduling priority would
/// trade all detection for a preference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerSetup {
    /// The platform needs nothing from the worker thread.
    ///
    /// A desktop system that schedules an ordinary thread correctly reports
    /// this, and it is not a gap.
    NothingToDo,

    /// The platform prepared the thread, and the text names what it did.
    Prepared {
        /// What the platform did. The text names the mechanism only.
        detail: BoundedText,
    },

    /// The preparation failed, and the worker runs anyway.
    Failed {
        /// Why it failed. The text names the mechanism only.
        detail: BoundedText,
    },
}

impl WorkerSetup {
    /// Reports whether the platform prepared the thread.
    #[must_use]
    pub const fn prepared(&self) -> bool {
        matches!(*self, Self::Prepared { .. })
    }
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::WorkerSetup;

    #[test]
    fn a_platform_that_needs_nothing_did_not_prepare_the_thread() {
        // The two must stay distinct. A platform that needs nothing is not a
        // platform that failed, and neither one prepared anything.
        assert!(!WorkerSetup::NothingToDo.prepared());
    }

    #[test]
    fn a_prepared_thread_reports_that_it_is_prepared() {
        let setup = WorkerSetup::Prepared {
            detail: BoundedText::new("the thread took a utility quality of service"),
        };
        assert!(setup.prepared());
    }

    #[test]
    fn a_failed_preparation_is_not_a_prepared_thread() {
        let setup = WorkerSetup::Failed {
            detail: BoundedText::new("the call failed"),
        };
        assert!(!setup.prepared());
    }
}
