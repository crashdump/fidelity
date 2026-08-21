use fidelity_types::{Category, CategorySet, Detector, DetectorState, Finding, Outcome, Snapshot};

#[derive(Debug, Clone)]
struct Slot {
    detector: Detector,
    outcome: Outcome,
    strongest: Option<Finding>,
    first_unix_ms: Option<u64>,
    latest_unix_ms: Option<u64>,
    occurrences: u32,
}

impl Slot {
    fn new(detector: Detector) -> Self {
        Self {
            detector,
            // A slot starts without coverage. A clean start would report a
            // result that no detector produced.
            outcome: Outcome::NotRun,
            strongest: None,
            first_unix_ms: None,
            latest_unix_ms: None,
            occurrences: 0,
        }
    }

    fn record(&mut self, outcome: Outcome) {
        if let Outcome::Finding(finding) = &outcome {
            let observed = finding.observed_at_unix_ms();
            self.first_unix_ms.get_or_insert(observed);
            self.latest_unix_ms = Some(observed);
            self.occurrences = self.occurrences.saturating_add(1);

            let stronger = self
                .strongest
                .as_ref()
                .is_none_or(|held| finding.strength() > held.strength());
            if stronger {
                self.strongest = Some(finding.clone());
            }
        }
        self.outcome = outcome;
    }

    fn to_public(&self) -> DetectorState {
        DetectorState::new(
            self.detector,
            self.outcome.clone(),
            self.strongest.clone(),
            self.first_unix_ms,
            self.latest_unix_ms,
            self.occurrences,
        )
    }
}

/// The retained state of one runtime.
///
/// The state holds one slot per built-in detector, and an observation cannot
/// create a slot. Nothing here grows with the number of findings, so a noisy
/// detector costs no memory beyond its own slot.
///
/// The engine keeps denial per runtime, so an isolated test runtime stays
/// independent of the process-wide latch that the facade owns.
#[derive(Debug, Clone)]
pub struct State {
    latched: CategorySet,
    host_latched: CategorySet,
    slots: Box<[Slot]>,
}

impl State {
    /// Creates the state for a fixed set of detectors.
    #[must_use]
    pub fn new(detectors: &[Detector]) -> Self {
        Self {
            latched: CategorySet::new(),
            host_latched: CategorySet::new(),
            slots: detectors
                .iter()
                .copied()
                .map(Slot::new)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    /// Records one scan outcome, and returns the finding that it carried.
    ///
    /// An outcome for an unknown detector changes nothing, because an
    /// observation cannot create a slot.
    pub fn record(&mut self, detector: Detector, outcome: Outcome) -> Option<Finding> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.detector == detector)?;
        let finding = outcome.finding().cloned();
        slot.record(outcome);
        finding
    }

    /// Latches a permanent denial for one category.
    ///
    /// The latch never clears. A recovery does not remove it.
    pub fn latch(&mut self, category: Category) {
        self.latched.insert(category);
    }

    /// Latches a permanent denial that the host asked for.
    ///
    /// The category denies exactly as a detector-driven latch does, and the
    /// snapshot keeps the two apart. A host latch has no finding behind it,
    /// so without the distinction a reader cannot explain the denial.
    pub fn latch_by_host(&mut self, category: Category) {
        self.latched.insert(category);
        self.host_latched.insert(category);
    }

    /// The categories that hold a permanent denial latch.
    #[must_use]
    pub fn latched(&self) -> CategorySet {
        self.latched
    }

    /// The categories that the host latched itself.
    #[must_use]
    pub fn host_latched(&self) -> CategorySet {
        self.host_latched
    }

    /// Builds the authoritative bounded state.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let detectors = self
            .slots
            .iter()
            .map(Slot::to_public)
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into_vec();
        Snapshot::new(self.latched, self.host_latched, detectors)
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use fidelity_types::{
        BoundedText, Category, Detector, DetectorState, Evidence, Finding, Outcome, SignalStrength,
    };

    const PROBE: Detector = Detector::new(1, "test.state", Category::Integrity);
    const OTHER: Detector = Detector::new(2, "test.other", Category::UiAbuse);
    const UNKNOWN: Detector = Detector::new(99, "test.unknown", Category::Debugging);

    fn finding(strength: SignalStrength, at: u64) -> Finding {
        Finding::new(
            PROBE,
            strength,
            Evidence::DetectorHealth {
                detail: BoundedText::new("detail"),
            },
            at,
        )
    }

    fn state() -> State {
        State::new(&[PROBE, OTHER])
    }

    fn slot_of(state: &State, detector: Detector) -> DetectorState {
        state
            .snapshot()
            .detector_state(detector)
            .cloned()
            .unwrap_or_else(|| DetectorState::new(detector, Outcome::NotRun, None, None, None, 0))
    }

    #[test]
    fn a_new_state_holds_one_slot_per_detector() {
        assert_eq!(state().snapshot().detectors().len(), 2);
    }

    #[test]
    fn a_new_state_latches_nothing() {
        assert!(state().latched().is_empty());
    }

    #[test]
    fn a_new_slot_reports_no_coverage() {
        assert_eq!(slot_of(&state(), PROBE).outcome(), &Outcome::NotRun);
    }

    #[test]
    fn a_new_slot_never_reads_as_clean() {
        assert!(!slot_of(&state(), PROBE).outcome().ran());
    }

    #[test]
    fn a_scan_replaces_the_absence_of_coverage() {
        let mut state = state();
        state.record(PROBE, Outcome::Clean);
        assert!(slot_of(&state, PROBE).outcome().ran());
    }

    #[test]
    fn recording_a_finding_returns_it() {
        let mut state = state();
        let returned = state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 5)));
        assert_eq!(returned, Some(finding(SignalStrength::Low, 5)));
    }

    #[test]
    fn recording_a_clean_outcome_returns_no_finding() {
        let mut state = state();
        assert_eq!(state.record(PROBE, Outcome::Clean), None);
    }

    #[test]
    fn an_unknown_detector_creates_no_slot() {
        let mut state = state();
        state.record(UNKNOWN, Outcome::Finding(finding(SignalStrength::High, 1)));
        assert_eq!(state.snapshot().detectors().len(), 2);
    }

    #[test]
    fn the_strongest_finding_never_decreases() {
        let mut state = state();
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::High, 1)));
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 2)));
        let strongest = slot_of(&state, PROBE).strongest().map(Finding::strength);
        assert_eq!(strongest, Some(SignalStrength::High));
    }

    #[test]
    fn a_recovery_keeps_the_strongest_finding() {
        let mut state = state();
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Medium, 1)));
        state.record(PROBE, Outcome::Clean);
        assert!(slot_of(&state, PROBE).strongest().is_some());
    }

    #[test]
    fn a_recovery_shows_a_clean_current_outcome() {
        let mut state = state();
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Medium, 1)));
        state.record(PROBE, Outcome::Clean);
        assert_eq!(slot_of(&state, PROBE).outcome(), &Outcome::Clean);
    }

    #[test]
    fn the_first_timestamp_stays_at_the_first_finding() {
        let mut state = state();
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 10)));
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 20)));
        assert_eq!(slot_of(&state, PROBE).first(), Some(10));
    }

    #[test]
    fn the_latest_timestamp_follows_the_last_finding() {
        let mut state = state();
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 10)));
        state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, 20)));
        assert_eq!(slot_of(&state, PROBE).latest(), Some(20));
    }

    #[test]
    fn repeated_findings_never_grow_the_state() {
        let mut state = state();
        for tick in 0..1_000 {
            state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, tick)));
        }
        assert_eq!(state.snapshot().detectors().len(), 2);
    }

    #[test]
    fn repeated_findings_count_up() {
        let mut state = state();
        for tick in 0..3 {
            state.record(PROBE, Outcome::Finding(finding(SignalStrength::Low, tick)));
        }
        assert_eq!(slot_of(&state, PROBE).occurrences(), 3);
    }

    #[test]
    fn a_host_latch_denies_its_category() {
        let mut state = state();
        state.latch_by_host(Category::Debugging);
        assert!(state.latched().contains(Category::Debugging));
    }

    #[test]
    fn a_host_latch_stays_distinguishable() {
        let mut state = state();
        state.latch(Category::Integrity);
        state.latch_by_host(Category::Debugging);
        assert!(state.host_latched().contains(Category::Debugging));
        assert!(!state.host_latched().contains(Category::Integrity));
    }

    #[test]
    fn a_detector_latch_never_reads_as_a_host_latch() {
        let mut state = state();
        state.latch(Category::Integrity);
        assert!(state.host_latched().is_empty());
    }

    #[test]
    fn a_latch_accumulates_and_never_clears() {
        let mut state = state();
        state.latch(Category::Integrity);
        state.latch(Category::UiAbuse);
        state.record(PROBE, Outcome::Clean);
        assert_eq!(state.latched().len(), 2);
    }

    #[test]
    fn an_unsupported_outcome_creates_no_history() {
        let mut state = state();
        state.record(
            PROBE,
            Outcome::Unsupported {
                reason: "the platform exposes no equivalent API",
            },
        );
        assert_eq!(slot_of(&state, PROBE).occurrences(), 0);
    }
}
