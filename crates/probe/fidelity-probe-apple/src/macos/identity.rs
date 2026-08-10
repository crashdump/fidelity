use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust, Signer};
use fidelity_types::{BoundedText, Choice, ExpectedIdentity};

use super::MacEnvironment;
use crate::sys::security::{OsStatus, SelfCode, Verdict, check, team_identifier};

/// The requirement that states platform trust on macOS.
///
/// The operating system validates the complete signature against an anchor
/// that Apple owns. A host that ships an ad-hoc or a self-signed build fails
/// this on every clean run, which is why the detector rates a rejection
/// `Medium` and not `High`.
const APPLE_ANCHOR: &str = "anchor apple generic";

/// The reason that an accepted gap reports.
const HOST_ACCEPTED_GAP: &str = "the host accepted no identity check on macOS";

/// The reason that an absent host value reports.
const NO_HOST_VALUE: &str = "the host stated no identity value for macOS";

impl Identity for MacEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        let code = match SelfCode::acquire() {
            Ok(code) => code,
            Err(status) => return Observation::failed(failure("SecCodeCopySelf", status)),
        };

        let trust = match check(&code, APPLE_ANCHOR) {
            Verdict::Pass => PlatformTrust::Accepted,
            Verdict::Reject(status) => PlatformTrust::Rejected {
                detail: BoundedText::new(format!(
                    "the running image does not satisfy \"{APPLE_ANCHOR}\", and \
                     SecCodeCheckValidity returned {status}"
                )),
            },
            Verdict::Error(status) => {
                return Observation::failed(failure("SecCodeCheckValidity", status));
            }
        };

        // An ad-hoc signature carries no team identifier. That is an absent
        // fact, not a failure, so the signer stays empty and the trust status
        // above states the finding.
        let signer = match team_identifier(&code) {
            Ok(Some(team)) => Some(Signer::new(
                team.clone().into_bytes(),
                format!("team {team}"),
            )),
            Ok(None) => None,
            Err(status) => {
                return Observation::failed(failure("SecCodeCopySigningInformation", status));
            }
        };

        Observation::Fact(CodeIdentity::new(trust, signer))
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let requirement = match expected.macos_choice() {
            Some(Choice::Value(requirement)) => requirement,
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

        let code = match SelfCode::acquire() {
            Ok(code) => code,
            Err(status) => return Observation::failed(failure("SecCodeCopySelf", status)),
        };

        match check(&code, requirement.as_str()) {
            Verdict::Pass => Observation::Fact(IdentityMatch::Same),
            Verdict::Reject(status) => Observation::Fact(IdentityMatch::Different {
                detail: BoundedText::new(format!(
                    "the running image does not satisfy the requirement that the host pinned, \
                     and SecCodeCheckValidity returned {status}"
                )),
            }),
            Verdict::Error(status) => Observation::failed(failure("SecCodeCheckValidity", status)),
        }
    }
}

/// Describes a failed call, in text that holds no application data.
fn failure(call: &str, status: OsStatus) -> String {
    format!("{call} returned {status}")
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Identity, IdentityMatch, Observation, PlatformTrust};
    use fidelity_types::{Choice, CodeRequirement, ExpectedIdentity, IdentityError};

    use crate::macos::MacEnvironment;

    /// Cargo signs a test binary ad hoc, so every test here runs against an
    /// image that satisfies no Apple anchor and carries no team identifier.
    /// That is the clean control for a locally built host.
    fn expected(requirement: &str) -> Result<ExpectedIdentity, IdentityError> {
        Ok(ExpectedIdentity::new().macos(Choice::Value(CodeRequirement::new(requirement)?)))
    }

    #[test]
    fn an_ad_hoc_image_reads_its_identity_without_a_failure() {
        let observation = MacEnvironment::new().code_identity();
        assert!(
            matches!(observation, Observation::Fact(_)),
            "the probe must read the fact, not fail: {observation:?}"
        );
    }

    #[test]
    fn an_ad_hoc_image_does_not_satisfy_the_apple_anchor() {
        let Observation::Fact(identity) = MacEnvironment::new().code_identity() else {
            unreachable!("the probe reads the fact on a signed test binary")
        };
        assert!(
            matches!(identity.trust(), PlatformTrust::Rejected { .. }),
            "Cargo signs the test binary ad hoc, so the anchor check must reject it"
        );
    }

    #[test]
    fn an_ad_hoc_image_carries_no_signer() {
        let Observation::Fact(identity) = MacEnvironment::new().code_identity() else {
            unreachable!("the probe reads the fact on a signed test binary")
        };
        assert!(
            identity.signer().is_none(),
            "an ad-hoc signature names no team"
        );
    }

    #[test]
    fn an_absent_host_value_reports_unsupported() {
        let observation = MacEnvironment::new().identity_match(&ExpectedIdentity::new());
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn an_accepted_gap_reports_unsupported() {
        let expected = ExpectedIdentity::new().macos(Choice::AcceptUnsupported);
        let observation = MacEnvironment::new().identity_match(&expected);
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn a_requirement_that_the_image_fails_reports_a_difference() -> Result<(), IdentityError> {
        let expected = expected("anchor apple generic")?;
        let observation = MacEnvironment::new().identity_match(&expected);
        assert!(
            matches!(
                observation,
                Observation::Fact(IdentityMatch::Different { .. })
            ),
            "an ad-hoc test binary satisfies no Apple anchor: {observation:?}"
        );
        Ok(())
    }

    #[test]
    fn a_requirement_that_the_image_meets_reports_a_match() -> Result<(), IdentityError> {
        // Cargo signs the test binary ad hoc, so it satisfies no Apple
        // anchor. The inverse requirement therefore holds, and it exercises
        // the match path without a distribution certificate.
        let expected = expected("!(anchor apple)")?;
        let observation = MacEnvironment::new().identity_match(&expected);
        assert!(
            matches!(observation, Observation::Fact(IdentityMatch::Same)),
            "the probe must report a match: {observation:?}"
        );
        Ok(())
    }

    #[test]
    fn a_requirement_that_does_not_parse_never_reads_as_a_match() -> Result<(), IdentityError> {
        let expected = expected("this is not a requirement")?;
        let observation = MacEnvironment::new().identity_match(&expected);
        assert!(
            matches!(observation, Observation::Failed { .. }),
            "a parse failure is a health finding, not a verdict: {observation:?}"
        );
        Ok(())
    }
}
