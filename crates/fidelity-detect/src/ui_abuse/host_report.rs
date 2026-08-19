use fidelity_types::{
    BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength, UiObservation,
};

/// The host reported that something reads or drives its user interface.
pub const HOST_REPORT: Detector = Detector::new(8, "ui_abuse.host_report", Category::UiAbuse);

/// The strength of a reported overlay.
///
/// `Medium`, and not `High`, because the first clause of `Medium` in the
/// [signal model](../../../../docs/plan/04-detectors-and-platforms.md) applies.
/// The evidence is direct: the operating system told the host that another
/// application sat above the window that took the touch. The benign case is
/// common, and it is what stops this reaching `High`. A screen dimmer, a
/// caption window, and an assistive overlay all produce the same flag, and each
/// one is a legitimate and protected use.
const OVERLAY_STRENGTH: SignalStrength = SignalStrength::Medium;

/// The strength of every observation except an overlay.
///
/// `Low`, and a reported screen capture is what lands here today. A person who
/// records their own screen is the ordinary explanation, and the signal model
/// puts a heuristic with a common benign explanation there. A host that
/// protects one screen lowers its threshold for this category and acts on it,
/// and a host that does not sees it in the snapshot and no more.
///
/// An observation that this build does not know reports here as well, because
/// nothing here measured it. A new observation that deserves more takes an arm
/// of its own, and a test below states that rule.
const OTHER_STRENGTH: SignalStrength = SignalStrength::Low;

/// Turns what the host observed into an outcome.
///
/// Fidelity decides the strength, and the host supplies the fact alone. A host
/// that stated its own strength would be stating policy, and the plan keeps
/// that here.
#[must_use]
pub fn host_report(observation: UiObservation, now_unix_ms: u64) -> Outcome {
    let strength = match observation {
        UiObservation::Overlay => OVERLAY_STRENGTH,
        // A reported screen capture lands here, and so does an observation
        // that this build does not know. The enumeration is `#[non_exhaustive]`
        // and it lives in another crate, so this arm is required and a new
        // variant reaches it in silence. Give one its own arm when it deserves
        // another strength.
        _ => OTHER_STRENGTH,
    };

    Outcome::Finding(Finding::new(
        HOST_REPORT,
        strength,
        Evidence::InterfaceObserved {
            detail: BoundedText::new(observation.detail()),
        },
        now_unix_ms,
    ))
}

#[cfg(test)]
mod tests {
    use fidelity_types::{Category, Evidence, Outcome, SignalStrength, UiObservation};

    use super::{HOST_REPORT, host_report};

    #[test]
    fn an_overlay_reports_at_medium() {
        let Outcome::Finding(finding) = host_report(UiObservation::Overlay, 0) else {
            panic!("a host report always creates a finding")
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
    }

    #[test]
    fn a_screen_capture_reports_at_low() {
        // A person who records their own screen is the ordinary case, so this
        // must not reach the default threshold on its own.
        let Outcome::Finding(finding) = host_report(UiObservation::ScreenCapture, 0) else {
            panic!("a host report always creates a finding")
        };
        assert_eq!(finding.strength(), SignalStrength::Low);
    }

    #[test]
    fn the_finding_reports_into_the_ui_abuse_category() {
        let Outcome::Finding(finding) = host_report(UiObservation::Overlay, 0) else {
            panic!("a host report always creates a finding")
        };
        assert_eq!(finding.category(), Category::UiAbuse);
    }

    #[test]
    fn the_evidence_states_what_the_host_reported() {
        let Outcome::Finding(finding) = host_report(UiObservation::Overlay, 0) else {
            panic!("a host report always creates a finding")
        };
        let Evidence::InterfaceObserved { detail } = finding.evidence() else {
            panic!("a host report carries interface evidence")
        };
        assert_eq!(detail.text(), UiObservation::Overlay.detail());
    }

    #[test]
    fn a_host_report_is_never_detector_health() {
        // Detector health describes Fidelity, and this describes the host's
        // environment, so `Action::Crash` must reach it.
        let Outcome::Finding(finding) = host_report(UiObservation::Overlay, 0) else {
            panic!("a host report always creates a finding")
        };
        assert!(!finding.evidence().is_detector_health());
    }

    #[test]
    fn the_detector_keeps_one_identity() {
        assert_eq!(HOST_REPORT.name(), "ui_abuse.host_report");
    }
}
