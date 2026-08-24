use fidelity_core::{BootVerification, Observation, VerifiedBoot};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// Android reports an unlocked or unverified boot state.
pub const VERIFIED_BOOT: Detector = Detector::new(
    10,
    "device_compromise.verified_boot",
    Category::DeviceCompromise,
);

/// Interprets what Android reports about boot verification.
pub(crate) fn verified_boot(
    environment: &(impl VerifiedBoot + ?Sized),
    now_unix_ms: u64,
) -> Outcome {
    match environment.boot_verification() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(BootVerification::Verified) => Outcome::Clean,
        Observation::Fact(BootVerification::Unverified { detail }) => {
            Outcome::Finding(Finding::new(
                VERIFIED_BOOT,
                SignalStrength::Medium,
                Evidence::UnverifiedBoot { detail },
                now_unix_ms,
            ))
        }
    }
}

/// Builds the `Low` finding that a failed probe produces.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        VERIFIED_BOOT,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{BootVerification, Observation};
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{BoundedText, Evidence, Outcome, SignalStrength};

    use super::verified_boot;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn a_verified_boot_reports_clean() {
        let environment = FakeEnvironment::new()
            .with_boot_verification(Observation::Fact(BootVerification::Verified));
        assert_eq!(verified_boot(&environment, NOW), Outcome::Clean);
    }

    #[test]
    fn an_unverified_boot_reports_a_medium_finding() {
        let environment = FakeEnvironment::new().with_boot_verification(Observation::Fact(
            BootVerification::Unverified {
                detail: BoundedText::new("Android reports an unlocked bootloader"),
            },
        ));
        let Outcome::Finding(finding) = verified_boot(&environment, NOW) else {
            panic!("an unverified boot must report a finding")
        };
        assert!(matches!(
            (finding.strength(), finding.evidence()),
            (SignalStrength::Medium, Evidence::UnverifiedBoot { .. })
        ));
    }

    #[test]
    fn a_failed_read_reports_a_low_health_finding() {
        let environment = FakeEnvironment::new()
            .with_boot_verification(Observation::failed("the property store reports a conflict"));
        let Outcome::Finding(finding) = verified_boot(&environment, NOW) else {
            panic!("a failed read must report a finding")
        };
        assert!(
            finding.strength() == SignalStrength::Low && finding.evidence().is_detector_health()
        );
    }

    #[test]
    fn an_unsupported_platform_reports_unsupported() {
        assert!(matches!(
            verified_boot(&FakeEnvironment::new(), NOW),
            Outcome::Unsupported { .. }
        ));
    }
}
