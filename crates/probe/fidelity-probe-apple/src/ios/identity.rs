//! Image identity on iOS.
//!
//! iOS answers the two tiers differently from macOS, and the reason is the
//! SDK rather than a design choice. Checked against the iOS 26 SDK on
//! 2026-08-10: the Security framework ships neither `SecCode.h` nor
//! `SecTask.h`, so nothing here can call `SecCodeCheckValidity` or
//! `SecCodeCopySigningInformation`.
//!
//! Platform trust therefore reports `Unavailable`. The kernel enforces code
//! signing before the image runs, so the question is already answered, and
//! there is no interface that reports the answer.
//!
//! Expected identity reads the team identifier out of the entitlements that
//! the image carries, which
//! [detectors and platforms](../../../../../docs/plan/04-detectors-and-platforms.md)
//! specifies as the App ID prefix. The boundary maps the bytes and the reader
//! in `fidelity-formats` parses them.

use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust, Signer};
use fidelity_formats::macho::{entitlements, signature};
use fidelity_types::{BoundedText, Choice, ExpectedIdentity};

use super::IosEnvironment;
use crate::sys::image;

/// Why iOS reports no platform trust.
const KERNEL_ENFORCES: &str = "the iOS kernel enforces code signing before the image runs, and \
                               the platform exposes no interface that reports the verdict";

/// The reason that an accepted gap reports.
const HOST_ACCEPTED_GAP: &str = "the host accepted no identity check on iOS";

/// The reason that an absent host value reports.
const NO_HOST_VALUE: &str = "the host stated no identity value for iOS";

/// What a pinned host value reports against an image that names no team.
const IMAGE_NAMES_NO_TEAM: &str =
    "the host pinned a team identifier, and the running image names none";

/// What a pinned host value reports against another team.
const ANOTHER_TEAM: &str =
    "the running image names a team identifier, and it is not the one the host pinned";

impl Identity for IosEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        // An image that names no team is an absent fact, not a failure. A
        // local build and a simulator build both reach it, so a failure here
        // would report a health finding on every clean developer run.
        let signer = team().map(|team| Signer::new(team.as_bytes(), format!("team {team}")));

        Observation::Fact(CodeIdentity::new(
            PlatformTrust::Unavailable {
                reason: KERNEL_ENFORCES,
            },
            signer,
        ))
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let pinned = match expected.ios_choice() {
            Some(Choice::Value(team)) => team,
            Some(Choice::AcceptUnsupported) => {
                return Observation::Unsupported {
                    reason: HOST_ACCEPTED_GAP,
                };
            }
            None => {
                return Observation::Unsupported {
                    reason: NO_HOST_VALUE,
                };
            }
        };

        Observation::Fact(compare(team(), pinned.as_str()))
    }
}

/// Compares the team that the image names against the team the host pinned.
///
/// The comparison is a plain function, because the positive answer needs an
/// image that a provisioned build signed. A test binary is signed ad hoc and
/// names no team, so only this shape proves every branch on any machine.
///
/// An absent team is a difference and not a failure. The host stated which
/// team signs its application, so an image that names none is not the image
/// that the host shipped.
fn compare(found: Option<&str>, pinned: &str) -> IdentityMatch {
    match found {
        Some(team) if team == pinned => IdentityMatch::Same,
        Some(_) => IdentityMatch::Different {
            detail: BoundedText::new(ANOTHER_TEAM),
        },
        None => IdentityMatch::Different {
            detail: BoundedText::new(IMAGE_NAMES_NO_TEAM),
        },
    }
}

/// The team identifier that the running image names.
///
/// The three layers meet here: the boundary maps the signature, one reader
/// finds the entitlements inside it, and another takes the team. Every value
/// borrows the mapped image, so the walk allocates nothing.
fn team() -> Option<&'static str> {
    let signature = image::code_signature()?;
    let plist = signature::entitlements(signature)?;
    entitlements::team_identifier(plist)
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Identity, IdentityMatch, Observation, PlatformTrust};
    use fidelity_types::{Choice, ExpectedIdentity, IdentityError, TeamIdentifier};

    use super::{IosEnvironment, compare, team};

    /// Cargo signs a test binary ad hoc, and an ad-hoc signature carries no
    /// entitlements, so every test here runs against an image that names no
    /// team. That is the clean control for a locally built host.
    fn pinned(value: &str) -> Result<ExpectedIdentity, IdentityError> {
        Ok(ExpectedIdentity::new().ios(Choice::Value(TeamIdentifier::new(value)?)))
    }

    #[test]
    fn the_probe_reads_its_identity_without_a_failure() {
        let observation = IosEnvironment::new().code_identity();
        assert!(
            matches!(observation, Observation::Fact(_)),
            "the probe must read the fact, not fail: {observation:?}"
        );
    }

    #[test]
    fn ios_reports_no_platform_trust() {
        let Observation::Fact(identity) = IosEnvironment::new().code_identity() else {
            unreachable!("the probe reads the fact on any signed image")
        };
        assert!(
            matches!(identity.trust(), PlatformTrust::Unavailable { .. }),
            "the SDK exposes no equivalent check, so the tier reports a gap"
        );
    }

    #[test]
    fn an_ad_hoc_image_carries_no_signer() {
        let Observation::Fact(identity) = IosEnvironment::new().code_identity() else {
            unreachable!("the probe reads the fact on any signed image")
        };
        assert_eq!(identity.signer().is_none(), team().is_none());
    }

    #[test]
    fn an_absent_host_value_reports_unsupported() {
        let observation = IosEnvironment::new().identity_match(&ExpectedIdentity::new());
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn an_accepted_gap_reports_unsupported() {
        let expected = ExpectedIdentity::new().ios(Choice::AcceptUnsupported);
        let observation = IosEnvironment::new().identity_match(&expected);
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn a_team_that_the_image_does_not_name_reports_a_difference() -> Result<(), IdentityError> {
        let observation = IosEnvironment::new().identity_match(&pinned("ABCDE12345")?);
        assert!(
            matches!(
                observation,
                Observation::Fact(IdentityMatch::Different { .. })
            ),
            "an ad-hoc test binary names no team: {observation:?}"
        );
        Ok(())
    }

    #[test]
    fn the_team_that_the_image_names_reports_a_match() {
        // The positive answer needs an image that a provisioned build signed,
        // and a test binary is not one. The comparison is therefore a plain
        // function, and this proves the branch that no test binary reaches.
        assert_eq!(
            compare(Some("ABCDE12345"), "ABCDE12345"),
            IdentityMatch::Same
        );
    }

    #[test]
    fn another_team_reports_a_difference() {
        assert!(matches!(
            compare(Some("OTHER99999"), "ABCDE12345"),
            IdentityMatch::Different { .. }
        ));
    }

    #[test]
    fn an_image_that_names_no_team_reports_a_difference() {
        // Never a match, and never a silent pass. The host pinned a team, so
        // an image without one is not the image that the host shipped.
        assert!(matches!(
            compare(None, "ABCDE12345"),
            IdentityMatch::Different { .. }
        ));
    }

    #[test]
    fn the_two_differences_explain_themselves_apart() {
        let (
            IdentityMatch::Different { detail: absent },
            IdentityMatch::Different { detail: other },
        ) = (
            compare(None, "ABCDE12345"),
            compare(Some("OTHER99999"), "ABCDE12345"),
        )
        else {
            unreachable!("both comparisons report a difference")
        };
        assert_ne!(absent.text(), other.text());
    }
}
