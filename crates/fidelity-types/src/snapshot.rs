use crate::{CategorySet, Detector, Finding, Outcome};

/// The retained state for one detector.
///
/// The runtime keeps one slot per built-in detector, and an observation
/// cannot create a slot. Each slot holds a fixed set of fields, so repeated
/// findings and recoveries never increase retained state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorState {
    detector: Detector,
    outcome: Outcome,
    strongest: Option<Finding>,
    first_unix_ms: Option<u64>,
    latest_unix_ms: Option<u64>,
    occurrences: u32,
}

impl DetectorState {
    /// Creates a detector state slot.
    ///
    /// Only Fidelity's own crates call this. It is not part of the supported
    /// surface, and it carries no compatibility promise.
    #[doc(hidden)]
    #[must_use]
    pub const fn new(
        detector: Detector,
        outcome: Outcome,
        strongest: Option<Finding>,
        first_unix_ms: Option<u64>,
        latest_unix_ms: Option<u64>,
        occurrences: u32,
    ) -> Self {
        Self {
            detector,
            outcome,
            strongest,
            first_unix_ms,
            latest_unix_ms,
            occurrences,
        }
    }

    /// The detector that owns this slot.
    #[must_use]
    pub const fn detector(&self) -> Detector {
        self.detector
    }

    /// What the most recent scan produced.
    ///
    /// A slot that no scan reached reads [`Outcome::NotRun`]. Check
    /// [`Outcome::ran`] before you treat this value as coverage.
    ///
    /// A detector that reads [`Outcome::Clean`] here can still hold a strong
    /// finding from an earlier scan, because a recovery never removes
    /// history.
    #[must_use]
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The strongest finding that this detector ever produced.
    ///
    /// The value never decreases.
    #[must_use]
    pub const fn strongest(&self) -> Option<&Finding> {
        self.strongest.as_ref()
    }

    /// When this detector first produced a finding.
    #[must_use]
    pub const fn first(&self) -> Option<u64> {
        self.first_unix_ms
    }

    /// When this detector last produced a finding.
    #[must_use]
    pub const fn latest(&self) -> Option<u64> {
        self.latest_unix_ms
    }

    /// How many findings this detector produced.
    ///
    /// The count saturates, so a noisy detector never wraps and never grows
    /// the retained state.
    #[must_use]
    pub const fn occurrences(&self) -> u32 {
        self.occurrences
    }
}

/// The authoritative bounded state of the runtime.
///
/// Fidelity does not persist a snapshot and does not serialize it for the
/// host. The host owns any durable history and chooses its own format.
///
/// The snapshot holds no event ring and no chronology, so nothing here grows
/// with the number of findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    latched: CategorySet,
    host_latched: CategorySet,
    detectors: Vec<DetectorState>,
}

impl Snapshot {
    /// Creates a snapshot.
    ///
    /// Only Fidelity's own crates call this. It is not part of the supported
    /// surface, and it carries no compatibility promise.
    #[doc(hidden)]
    #[must_use]
    pub const fn new(
        latched: CategorySet,
        host_latched: CategorySet,
        detectors: Vec<DetectorState>,
    ) -> Self {
        Self {
            latched,
            host_latched,
            detectors,
        }
    }

    /// The categories that hold a permanent denial latch.
    ///
    /// This covers every latch, whatever set it. A latch never clears, and a
    /// recovery does not remove it.
    #[must_use]
    pub const fn latched_categories(&self) -> CategorySet {
        self.latched
    }

    /// The categories that the host latched itself.
    ///
    /// These are a subset of [`latched_categories`](Snapshot::latched_categories).
    /// A category appears here when the host called
    /// `Handle::deny`, so a denial with no detector finding behind it stays
    /// explainable.
    #[must_use]
    pub const fn host_latched_categories(&self) -> CategorySet {
        self.host_latched
    }

    /// Every detector state slot, in a stable order.
    #[must_use]
    pub fn detectors(&self) -> &[DetectorState] {
        &self.detectors
    }

    /// The state slot for one detector.
    #[must_use]
    pub fn detector_state(&self, detector: Detector) -> Option<&DetectorState> {
        self.detectors
            .iter()
            .find(|state| state.detector() == detector)
    }
}

#[cfg(test)]
mod tests {
    use super::{DetectorState, Snapshot};
    use crate::{
        BoundedText, Category, CategorySet, Detector, Evidence, Finding, Outcome, SignalStrength,
    };

    const FIRST: Detector = Detector::new(1, "test.first", Category::Integrity);
    const SECOND: Detector = Detector::new(2, "test.second", Category::UiAbuse);

    fn finding(detector: Detector, strength: SignalStrength) -> Finding {
        Finding::new(
            detector,
            strength,
            Evidence::DetectorHealth {
                detail: BoundedText::new("detail"),
            },
            10,
        )
    }

    fn snapshot() -> Snapshot {
        let mut latched = CategorySet::new();
        latched.insert(Category::Integrity);
        let mut host_latched = CategorySet::new();
        host_latched.insert(Category::UiAbuse);
        latched.insert(Category::UiAbuse);
        Snapshot::new(
            latched,
            host_latched,
            vec![
                DetectorState::new(
                    FIRST,
                    Outcome::Clean,
                    Some(finding(FIRST, SignalStrength::High)),
                    Some(10),
                    Some(20),
                    3,
                ),
                DetectorState::new(SECOND, Outcome::Clean, None, None, None, 0),
            ],
        )
    }

    #[test]
    fn a_snapshot_reports_its_latched_categories() {
        assert!(
            snapshot()
                .latched_categories()
                .contains(Category::Integrity)
        );
    }

    #[test]
    fn a_snapshot_separates_a_host_latch_from_a_detector_latch() {
        let snapshot = snapshot();
        let host = snapshot.host_latched_categories();
        assert!(
            host.contains(Category::UiAbuse),
            "the host latch is missing"
        );
        assert!(
            !host.contains(Category::Integrity),
            "a detector latch must not read as a host latch"
        );
    }

    #[test]
    fn every_host_latch_also_denies() {
        let snapshot = snapshot();
        for category in Category::ALL {
            if snapshot.host_latched_categories().contains(category) {
                assert!(
                    snapshot.latched_categories().contains(category),
                    "{category:?} latched by the host but not denied"
                );
            }
        }
    }

    #[test]
    fn a_snapshot_holds_one_slot_per_detector() {
        assert_eq!(snapshot().detectors().len(), 2);
    }

    #[test]
    fn a_snapshot_finds_a_slot_by_detector() {
        let snapshot = snapshot();
        let state = snapshot.detector_state(SECOND);
        assert_eq!(state.map(DetectorState::detector), Some(SECOND));
    }

    #[test]
    fn a_clean_slot_still_reports_its_strongest_finding() {
        let snapshot = snapshot();
        let state = snapshot.detector_state(FIRST);
        let strongest = state.and_then(DetectorState::strongest);
        assert_eq!(strongest.map(Finding::strength), Some(SignalStrength::High));
    }

    #[test]
    fn a_slot_without_history_reports_no_strongest_finding() {
        let snapshot = snapshot();
        let state = snapshot.detector_state(SECOND);
        assert!(state.and_then(DetectorState::strongest).is_none());
    }

    #[test]
    fn a_slot_reports_its_occurrence_count() {
        let snapshot = snapshot();
        let count = snapshot
            .detector_state(FIRST)
            .map(DetectorState::occurrences);
        assert_eq!(count, Some(3));
    }
}
