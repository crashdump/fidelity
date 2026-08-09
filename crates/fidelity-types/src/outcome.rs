use crate::Finding;

/// What one scan of one detector produced.
///
/// Each scan gives a detector exactly one outcome, and a detector that no
/// scan touched holds [`NotRun`](Outcome::NotRun). An unexpected API failure
/// is neither [`Clean`](Outcome::Clean) nor
/// [`Unsupported`](Outcome::Unsupported): it is a `Low` detector-health
/// [`Finding`].
///
/// The enumeration stays exhaustive, so a host match needs no wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The check did not run.
    ///
    /// Every state slot starts here. The initial scan runs the cheap
    /// detectors only, so an expensive detector keeps this outcome until the
    /// worker completes its first cycle.
    ///
    /// This is not a clean result. A host that reads it as one believes in
    /// coverage that no detector produced.
    NotRun,

    /// The check ran and found nothing.
    Clean,

    /// The check ran and found something.
    Finding(Finding),

    /// The check cannot run here.
    ///
    /// This is metadata. It never enters policy, it creates no finding, and
    /// it triggers no action. A platform that lacks a mechanism reports it
    /// here rather than through a conditional public type.
    Unsupported {
        /// Why the check cannot run on this target.
        reason: &'static str,
    },
}

impl Outcome {
    /// Returns the finding, when this outcome carries one.
    #[must_use]
    pub const fn finding(&self) -> Option<&Finding> {
        match self {
            Self::Finding(finding) => Some(finding),
            Self::NotRun | Self::Clean | Self::Unsupported { .. } => None,
        }
    }

    /// Reports whether the check ran on this target.
    ///
    /// A clean result and a finding both mean the check ran. A check that the
    /// platform cannot support, and a check that no scan reached yet, both
    /// mean it did not. Only this method separates real coverage from the
    /// absence of coverage.
    #[must_use]
    pub const fn ran(&self) -> bool {
        matches!(self, Self::Clean | Self::Finding(_))
    }
}

#[cfg(test)]
mod tests {
    use super::Outcome;
    use crate::{BoundedText, Category, Detector, Evidence, Finding, SignalStrength};

    const PROBE: Detector = Detector::new(3, "test.outcome", Category::Debugging);

    fn finding() -> Finding {
        Finding::new(
            PROBE,
            SignalStrength::Medium,
            Evidence::DetectorHealth {
                detail: BoundedText::new("detail"),
            },
            0,
        )
    }

    #[test]
    fn a_clean_outcome_carries_no_finding() {
        assert!(Outcome::Clean.finding().is_none());
    }

    #[test]
    fn an_outcome_that_did_not_run_carries_no_finding() {
        assert!(Outcome::NotRun.finding().is_none());
    }

    #[test]
    fn an_unsupported_outcome_carries_no_finding() {
        let outcome = Outcome::Unsupported {
            reason: "the platform exposes no equivalent API",
        };
        assert!(outcome.finding().is_none());
    }

    #[test]
    fn a_finding_outcome_carries_its_finding() {
        let outcome = Outcome::Finding(finding());
        assert_eq!(outcome.finding(), Some(&finding()));
    }

    #[test]
    fn a_clean_check_ran() {
        assert!(Outcome::Clean.ran());
    }

    #[test]
    fn an_unsupported_check_did_not_run() {
        let outcome = Outcome::Unsupported { reason: "no API" };
        assert!(!outcome.ran());
    }

    #[test]
    fn a_check_that_no_scan_reached_did_not_run() {
        assert!(!Outcome::NotRun.ran());
    }

    #[test]
    fn a_finding_means_the_check_ran() {
        assert!(Outcome::Finding(finding()).ran());
    }
}
