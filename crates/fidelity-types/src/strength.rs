/// The evidential quality of one finding.
///
/// This describes how good the evidence is. It does not describe impact and
/// it does not describe severity. Impact and application sensitivity stay
/// host concerns.
///
/// The three levels are ordered, so a threshold comparison is a comparison of
/// two values. Fidelity never adds weak signals, calculates a score, decays
/// evidence, or escalates a repeated detector failure.
///
/// The enumeration stays exhaustive, so a host match needs no wildcard arm.
///
/// # Examples
///
/// ```
/// use fidelity_types::SignalStrength;
///
/// assert!(SignalStrength::High > SignalStrength::Medium);
/// assert!(SignalStrength::Medium > SignalStrength::Low);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum SignalStrength {
    /// An ambiguous posture, a health failure, or a heuristic with common
    /// benign explanations.
    Low,

    /// Direct evidence with known legitimate cases, or with a meaningful
    /// user-mode bypass.
    Medium,

    /// Direct evidence whose benign explanation is structurally rare on the
    /// supported target.
    High,
}

impl SignalStrength {
    /// Every strength, from the weakest to the strongest.
    pub const ALL: [Self; 3] = [Self::Low, Self::Medium, Self::High];

    /// Reports whether this strength reaches the threshold.
    ///
    /// A finding qualifies for an action when it is at or above the category
    /// threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// use fidelity_types::SignalStrength;
    ///
    /// assert!(SignalStrength::High.reaches(SignalStrength::Medium));
    /// assert!(SignalStrength::Medium.reaches(SignalStrength::Medium));
    /// assert!(!SignalStrength::Low.reaches(SignalStrength::Medium));
    /// ```
    #[must_use]
    pub fn reaches(self, threshold: Self) -> bool {
        self >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::SignalStrength;

    #[test]
    fn strengths_order_from_low_to_high() {
        assert!(SignalStrength::Low < SignalStrength::Medium);
        assert!(SignalStrength::Medium < SignalStrength::High);
    }

    #[test]
    fn a_strength_reaches_its_own_threshold() {
        assert!(SignalStrength::Low.reaches(SignalStrength::Low));
    }

    #[test]
    fn a_weaker_strength_does_not_reach_a_higher_threshold() {
        assert!(!SignalStrength::Medium.reaches(SignalStrength::High));
    }

    #[test]
    fn all_lists_every_strength_in_order() {
        assert_eq!(
            SignalStrength::ALL,
            [
                SignalStrength::Low,
                SignalStrength::Medium,
                SignalStrength::High
            ]
        );
    }
}
