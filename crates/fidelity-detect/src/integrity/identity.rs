use fidelity_core::{Identity, IdentityMatch, Observation, PlatformTrust};
use fidelity_types::{
    BoundedText, Category, Detector, Evidence, ExpectedIdentity, Finding, Outcome, SignalStrength,
};

/// The operating system accepts the running image.
///
/// This is the platform-trust tier, and it needs no host input.
pub const PLATFORM_TRUST: Detector =
    Detector::new(1, "integrity.platform_trust", Category::Integrity);

/// The running image satisfies the identity that the host pinned.
///
/// This is the expected-identity tier. It is the only local evidence that
/// identifies a repackaged application.
pub const EXPECTED_IDENTITY: Detector =
    Detector::new(2, "integrity.expected_identity", Category::Integrity);

/// The strength of a rejected image.
///
/// Measured on macOS 26 and ARM64: a host that ships an ad-hoc or a
/// self-signed build fails the anchor check on every clean run, so the benign
/// case is real and common. That is the definition of `Medium`. A host that
/// signs for distribution, and wants the check to act, lowers the `Integrity`
/// threshold. A second platform assigns its own strength when its backend
/// lands with clean and hostile evidence.
const REJECTED_STRENGTH: SignalStrength = SignalStrength::Medium;

/// The strength of an image that does not satisfy the pinned identity.
///
/// The host supplied the value, so a mismatch states that the running image is
/// not the image the host shipped. Certificate rotation is the one benign
/// case, and the host controls it.
const UNEXPECTED_STRENGTH: SignalStrength = SignalStrength::High;

/// The reason an absent host value gives.
const NO_HOST_VALUE: &str = "the host supplied no expected identity";

/// Interprets what the operating system reports about image trust.
pub(crate) fn platform_trust(environment: &(impl Identity + ?Sized), now_unix_ms: u64) -> Outcome {
    match environment.code_identity() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(PLATFORM_TRUST, detail, now_unix_ms),
        Observation::Fact(identity) => match identity.trust() {
            PlatformTrust::Accepted => Outcome::Clean,
            PlatformTrust::Unavailable { reason } => Outcome::Unsupported { reason },
            PlatformTrust::Rejected { detail } => Outcome::Finding(Finding::new(
                PLATFORM_TRUST,
                REJECTED_STRENGTH,
                Evidence::ImageUntrusted {
                    detail: detail.clone(),
                },
                now_unix_ms,
            )),
        },
    }
}

/// Interprets whether the running image satisfies the pinned identity.
pub(crate) fn expected_identity(
    environment: &(impl Identity + ?Sized),
    expected: Option<&ExpectedIdentity>,
    now_unix_ms: u64,
) -> Outcome {
    let Some(expected) = expected else {
        return Outcome::Unsupported {
            reason: NO_HOST_VALUE,
        };
    };

    match environment.identity_match(expected) {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(EXPECTED_IDENTITY, detail, now_unix_ms),
        Observation::Fact(IdentityMatch::Same) => Outcome::Clean,
        Observation::Fact(IdentityMatch::Different { detail }) => Outcome::Finding(Finding::new(
            EXPECTED_IDENTITY,
            UNEXPECTED_STRENGTH,
            Evidence::UnexpectedIdentity { detail },
            now_unix_ms,
        )),
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detector: Detector, detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        detector,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
