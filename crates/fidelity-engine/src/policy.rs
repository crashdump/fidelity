use fidelity_types::{Action, Category, Finding, SignalStrength};

#[derive(Debug, Clone, Copy)]
struct Entry {
    action: Action,
    threshold: SignalStrength,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            action: Action::Report,
            threshold: SignalStrength::High,
        }
    }
}

/// The action and the threshold that the host selected for each category.
///
/// Every category starts at `Report` with a `High` threshold. A lower
/// threshold accepts weaker evidence and more false positives, so it is an
/// explicit host choice.
///
/// The policy is immutable once the runtime starts.
#[derive(Debug, Clone)]
pub struct Policy {
    entries: [Entry; Category::COUNT],
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy {
    /// Creates a policy where every category reports high-strength findings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: [Entry::default(); Category::COUNT],
        }
    }

    /// Sets the action and the threshold for one category.
    ///
    /// The two arrive together, because they are one risk decision.
    pub fn set(&mut self, category: Category, action: Action, threshold: SignalStrength) {
        self.entries[category.index()] = Entry { action, threshold };
    }

    /// The action for one category.
    #[must_use]
    pub fn action(&self, category: Category) -> Action {
        self.entries[category.index()].action
    }

    /// The threshold for one category.
    #[must_use]
    pub fn threshold(&self, category: Category) -> SignalStrength {
        self.entries[category.index()].threshold
    }

    /// Reports whether any category selects [`Action::Callback`].
    ///
    /// A host that selects the action must supply a callback at start.
    #[must_use]
    pub fn needs_callback(&self) -> bool {
        Category::ALL
            .iter()
            .any(|category| self.action(*category) == Action::Callback)
    }

    /// The action that this finding qualifies for.
    ///
    /// Returns `None` when the finding sits below its category threshold.
    /// Fidelity still reports every finding, so a `None` here means no
    /// action, not a discarded observation.
    ///
    /// `Action::Crash` never fires on a detector-health finding. Such a
    /// finding describes Fidelity, not the host's environment, so it reports
    /// instead. A host that selects `Crash` with a `Low` threshold would
    /// otherwise let anything that breaks one detector terminate the process.
    #[must_use]
    pub fn qualifying_action(&self, finding: &Finding) -> Option<Action> {
        let category = finding.category();
        if !finding.strength().reaches(self.threshold(category)) {
            return None;
        }
        let action = self.action(category);
        if action == Action::Crash && finding.evidence().is_detector_health() {
            return Some(Action::Report);
        }
        Some(action)
    }
}

#[cfg(test)]
mod tests {
    use super::Policy;
    use fidelity_types::{
        Action, BoundedText, Category, Detector, Evidence, Finding, SignalStrength,
    };

    const PROBE: Detector = Detector::new(1, "test.policy", Category::Debugging);

    fn finding(strength: SignalStrength) -> Finding {
        Finding::new(
            PROBE,
            strength,
            Evidence::DetectorHealth {
                detail: BoundedText::new("detail"),
            },
            0,
        )
    }

    #[test]
    fn every_category_defaults_to_report() {
        let policy = Policy::new();
        for category in Category::ALL {
            assert_eq!(policy.action(category), Action::Report, "{category:?}");
        }
    }

    #[test]
    fn every_category_defaults_to_a_high_threshold() {
        let policy = Policy::new();
        for category in Category::ALL {
            assert_eq!(
                policy.threshold(category),
                SignalStrength::High,
                "{category:?}"
            );
        }
    }

    #[test]
    fn a_setting_reaches_only_its_own_category() {
        let mut policy = Policy::new();
        policy.set(Category::Integrity, Action::Crash, SignalStrength::Low);
        assert_eq!(policy.action(Category::Debugging), Action::Report);
    }

    #[test]
    fn a_finding_at_the_threshold_qualifies() {
        let mut policy = Policy::new();
        policy.set(Category::Debugging, Action::Deny, SignalStrength::Medium);
        let action = policy.qualifying_action(&finding(SignalStrength::Medium));
        assert_eq!(action, Some(Action::Deny));
    }

    #[test]
    fn a_finding_below_the_threshold_qualifies_for_nothing() {
        let mut policy = Policy::new();
        policy.set(Category::Debugging, Action::Deny, SignalStrength::High);
        assert_eq!(
            policy.qualifying_action(&finding(SignalStrength::Low)),
            None
        );
    }

    #[test]
    fn a_crash_never_fires_on_a_detector_health_finding() {
        let mut policy = Policy::new();
        policy.set(Category::Debugging, Action::Crash, SignalStrength::Low);
        let action = policy.qualifying_action(&finding(SignalStrength::Low));
        assert_eq!(
            action,
            Some(Action::Report),
            "a failure of Fidelity's own check must not stop the host process"
        );
    }

    #[test]
    fn a_health_finding_still_reaches_every_other_action() {
        for action in [Action::Report, Action::Deny, Action::Callback] {
            let mut policy = Policy::new();
            policy.set(Category::Debugging, action, SignalStrength::Low);
            let qualified = policy.qualifying_action(&finding(SignalStrength::Low));
            assert_eq!(qualified, Some(action), "{action:?} was downgraded");
        }
    }

    #[test]
    fn a_health_finding_below_the_threshold_still_qualifies_for_nothing() {
        let mut policy = Policy::new();
        policy.set(Category::Debugging, Action::Crash, SignalStrength::High);
        assert_eq!(
            policy.qualifying_action(&finding(SignalStrength::Low)),
            None,
            "the threshold applies before the crash exemption"
        );
    }

    #[test]
    fn a_default_policy_needs_no_callback() {
        assert!(!Policy::new().needs_callback());
    }

    #[test]
    fn one_callback_category_needs_a_callback() {
        let mut policy = Policy::new();
        policy.set(Category::UiAbuse, Action::Callback, SignalStrength::High);
        assert!(policy.needs_callback());
    }
}
