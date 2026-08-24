use fidelity_core::{LocalAgent, LocalAgentState, Observation};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// A compatible local instrumentation endpoint answered on loopback.
pub const LOCAL_AGENT: Detector =
    Detector::new(11, "instrumentation.local_agent", Category::Instrumentation);

/// Interprets the bounded loopback protocol exchange.
pub(crate) fn local_agent(environment: &(impl LocalAgent + ?Sized), now_unix_ms: u64) -> Outcome {
    match environment.local_agent_state() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(LocalAgentState::Absent) => Outcome::Clean,
        Observation::Fact(LocalAgentState::Present { detail }) => Outcome::Finding(Finding::new(
            LOCAL_AGENT,
            SignalStrength::Medium,
            Evidence::LocalInstrumentationAgent { detail },
            now_unix_ms,
        )),
    }
}

/// Builds the `Low` finding that a failed probe produces.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        LOCAL_AGENT,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{LocalAgentState, Observation};
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{BoundedText, Evidence, Outcome, SignalStrength};

    use super::local_agent;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn an_absent_endpoint_reports_clean() {
        let environment =
            FakeEnvironment::new().with_local_agent(Observation::Fact(LocalAgentState::Absent));
        assert_eq!(local_agent(&environment, NOW), Outcome::Clean);
    }

    #[test]
    fn a_compatible_endpoint_reports_a_medium_finding() {
        let environment =
            FakeEnvironment::new().with_local_agent(Observation::Fact(LocalAgentState::Present {
                detail: BoundedText::new("a Frida-compatible endpoint answered"),
            }));
        let Outcome::Finding(finding) = local_agent(&environment, NOW) else {
            panic!("a compatible endpoint must report a finding")
        };
        assert!(matches!(
            (finding.strength(), finding.evidence()),
            (
                SignalStrength::Medium,
                Evidence::LocalInstrumentationAgent { .. }
            )
        ));
    }

    #[test]
    fn a_failed_exchange_reports_a_low_health_finding() {
        let environment = FakeEnvironment::new().with_local_agent(Observation::failed(
            "the loopback read reached its deadline",
        ));
        let Outcome::Finding(finding) = local_agent(&environment, NOW) else {
            panic!("a failed exchange must report a finding")
        };
        assert!(
            finding.strength() == SignalStrength::Low && finding.evidence().is_detector_health()
        );
    }

    #[test]
    fn an_unsupported_probe_reports_unsupported() {
        assert!(matches!(
            local_agent(&FakeEnvironment::new(), NOW),
            Outcome::Unsupported { .. }
        ));
    }
}
