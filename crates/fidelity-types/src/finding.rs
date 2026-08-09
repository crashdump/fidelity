use crate::{Category, Detector, Evidence, SignalStrength};

/// One observation that a detector produced.
///
/// A finding is permanent history. A recovery can make a detector healthy
/// again, but it neither removes the finding nor clears the category latch.
///
/// Findings are unauthenticated. An application must not treat one as
/// evidence against an attacker who controls the process.
///
/// # The category is separate from the detector
///
/// A finding carries its own [`Category`], and that category is usually the
/// detector's own. It differs when the runtime records a health finding on
/// behalf of another category. A panic inside the host callback is the case
/// that v1 defines: the runtime records it in the category of the finding
/// that the callback received, not in a category of its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    detector: Detector,
    category: Category,
    strength: SignalStrength,
    evidence: Evidence,
    observed_at_unix_ms: u64,
}

impl Finding {
    /// Creates a finding in the detector's own category.
    ///
    /// Only Fidelity's own crates call this. It is not part of the supported
    /// surface, and it carries no compatibility promise.
    #[doc(hidden)]
    #[must_use]
    pub fn new(
        detector: Detector,
        strength: SignalStrength,
        evidence: Evidence,
        observed_at_unix_ms: u64,
    ) -> Self {
        Self::in_category(
            detector,
            detector.category(),
            strength,
            evidence,
            observed_at_unix_ms,
        )
    }

    /// Creates a finding in a stated category.
    ///
    /// Only Fidelity's own crates call this. It is not part of the supported
    /// surface, and it carries no compatibility promise.
    #[doc(hidden)]
    #[must_use]
    pub const fn in_category(
        detector: Detector,
        category: Category,
        strength: SignalStrength,
        evidence: Evidence,
        observed_at_unix_ms: u64,
    ) -> Self {
        Self {
            detector,
            category,
            strength,
            evidence,
            observed_at_unix_ms,
        }
    }

    /// The detector that produced this finding.
    #[must_use]
    pub const fn detector(&self) -> Detector {
        self.detector
    }

    /// The category that carries this finding.
    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    /// How good the evidence is.
    #[must_use]
    pub const fn strength(&self) -> SignalStrength {
        self.strength
    }

    /// The typed detail that explains this finding.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// When the detector observed this, in milliseconds since the Unix epoch.
    ///
    /// The wall-clock timestamp is informational and it may move backwards.
    /// Nothing streams, so nothing needs an order.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

#[cfg(test)]
mod tests {
    use super::Finding;
    use crate::{BoundedText, Category, Detector, Evidence, SignalStrength};

    const PROBE: Detector = Detector::new(7, "test.probe", Category::Instrumentation);

    fn health() -> Evidence {
        Evidence::DetectorHealth {
            detail: BoundedText::new("the API returned an error"),
        }
    }

    #[test]
    fn a_finding_takes_the_detector_category_by_default() {
        let finding = Finding::new(PROBE, SignalStrength::Low, health(), 0);
        assert_eq!(finding.category(), Category::Instrumentation);
    }

    #[test]
    fn a_finding_can_carry_another_category() {
        let finding =
            Finding::in_category(PROBE, Category::UiAbuse, SignalStrength::Low, health(), 0);
        assert_eq!(finding.category(), Category::UiAbuse);
    }

    #[test]
    fn a_relabelled_finding_keeps_its_detector() {
        let finding =
            Finding::in_category(PROBE, Category::UiAbuse, SignalStrength::Low, health(), 0);
        assert_eq!(finding.detector(), PROBE);
    }

    #[test]
    fn a_finding_reports_its_strength() {
        let finding = Finding::new(PROBE, SignalStrength::High, health(), 42);
        assert_eq!(finding.strength(), SignalStrength::High);
    }

    #[test]
    fn a_finding_reports_its_timestamp() {
        let finding = Finding::new(PROBE, SignalStrength::High, health(), 42);
        assert_eq!(finding.observed_at_unix_ms(), 42);
    }
}
