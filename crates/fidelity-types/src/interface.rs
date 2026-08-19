/// What the host observed on a window that it owns.
///
/// Every other category reads the operating system. This one cannot, and a
/// measurement settled that rather than a preference. Measured on Android 37 on
/// 2026-08-19: no interface states that another application draws above this
/// one. The evidence is a flag on the touch that a `View` receives, and a
/// library holds no `View`. The host does, so the host reads it and reports it
/// here.
///
/// The host reports a fact, and Fidelity decides the strength and the evidence
/// from it. A host that could state its own strength would be stating policy,
/// and `docs/plan/04-detectors-and-platforms.md` keeps that with Fidelity.
///
/// The enumeration is `#[non_exhaustive]`, because the category covers more
/// than these two and each one arrives with the platform reading that proves a
/// host can make it.
///
/// `Handle::report_ui_abuse` takes it, and that method holds the example.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum UiObservation {
    /// Another application drew over a window of this application.
    ///
    /// Android states this on the touch itself, as
    /// `MotionEvent.FLAG_WINDOW_IS_OBSCURED` and its partial form. A host that
    /// reads either flag reports this.
    Overlay,

    /// A recorder captured a window of this application.
    ///
    /// Android states this through `WindowManager.addScreenRecordingCallback`,
    /// which reports the activities of the calling uid. A host that registers
    /// that callback reports this when the state turns visible.
    ScreenCapture,
}

impl UiObservation {
    /// What this observation states, in text that holds no application data.
    ///
    /// The text names the mechanism and never the window, the view, or
    /// anything a person typed.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Overlay => "the host reports that another application drew over its window",
            Self::ScreenCapture => "the host reports that a recorder captured its window",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UiObservation;

    #[test]
    fn each_observation_states_its_own_mechanism() {
        assert_ne!(
            UiObservation::Overlay.detail(),
            UiObservation::ScreenCapture.detail()
        );
    }

    #[test]
    fn the_detail_names_no_window_and_no_view() {
        // The text reaches whatever log the host sends its own logs to, so it
        // must carry nothing that a person typed or that names their screen.
        for observation in [UiObservation::Overlay, UiObservation::ScreenCapture] {
            let detail = observation.detail();
            assert!(detail.starts_with("the host reports that"), "{detail}");
        }
    }
}
