use fidelity_types::BoundedText;

/// What a probe read from one operating-system interface.
///
/// The three cases stay separate until the detector interprets them, because
/// Fidelity never converts a probe error into a clean result. A detector maps
/// `Failed` to a `Low` detector-health finding. It maps `Unsupported` to
/// capability metadata, which creates no finding and no action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation<T> {
    /// The probe read the fact.
    Fact(T),

    /// The platform exposes no interface for this fact.
    Unsupported {
        /// Why the fact cannot exist on this platform.
        reason: &'static str,
    },

    /// The interface exists, and the call failed.
    Failed {
        /// What failed, in text that holds no application data.
        detail: BoundedText,
    },
}

impl<T> Observation<T> {
    /// Creates a failure from text.
    ///
    /// The text explains the operating-system call that failed. It must hold
    /// no application data.
    #[must_use]
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: BoundedText::new(detail),
        }
    }

    /// The fact, when the probe read one.
    #[must_use]
    pub fn fact(&self) -> Option<&T> {
        match self {
            Self::Fact(fact) => Some(fact),
            Self::Unsupported { .. } | Self::Failed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Observation;

    #[test]
    fn a_fact_reads_back() {
        let observation = Observation::Fact(7_u8);
        assert_eq!(observation.fact(), Some(&7));
    }

    #[test]
    fn an_unsupported_observation_holds_no_fact() {
        let observation: Observation<u8> = Observation::Unsupported { reason: "no API" };
        assert_eq!(observation.fact(), None);
    }

    #[test]
    fn a_failure_holds_no_fact() {
        let observation: Observation<u8> = Observation::failed("the call returned -1");
        assert_eq!(observation.fact(), None);
    }

    #[test]
    fn a_failure_keeps_its_detail() {
        let observation: Observation<u8> = Observation::failed("the call returned -1");
        let Observation::Failed { detail } = observation else {
            unreachable!("the constructor builds a failure")
        };
        assert_eq!(detail.text(), "the call returned -1");
    }
}
