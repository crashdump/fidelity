//! Image identity on Windows.
//!
//! Windows carries both tiers, and it is the only platform besides macOS that
//! does. `WinVerifyTrust` answers the platform-trust question with no host
//! input, and the signer certificate answers the expected-identity question
//! against a value the host pinned.
//!
//! The pinned value is a SHA-256 digest of the signer certificate, and not the
//! value that Windows tooling calls a thumbprint. A thumbprint there is always
//! SHA-1. [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! records that trap, because the certificate view puts the wrong value in
//! front of a host.

use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust, Signer};
use fidelity_types::{BoundedText, Choice, ExpectedIdentity};

use crate::WindowsEnvironment;
use crate::sys::{crypt, image, wintrust};

/// What an unsigned image reports for the platform-trust tier.
const UNSIGNED: &str = "the running image carries no Authenticode signature";

/// What an image with a signature that failed reports.
const NOT_TRUSTED: &str = "the Authenticode signature of the running image did not validate";

/// The reason that an accepted gap reports.
const HOST_ACCEPTED_GAP: &str = "the host accepted no identity check on Windows";

/// The reason that an absent host value reports.
const NO_HOST_VALUE: &str = "the host stated no identity value for Windows";

/// What a pinned host value reports against another signer.
const ANOTHER_SIGNER: &str = "the running image carries another signing certificate";

impl Identity for WindowsEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        let Ok(path) = image::path() else {
            return Observation::failed("the running image named no path");
        };

        let trust = match wintrust::verify(&path) {
            wintrust::Trust::Accepted => PlatformTrust::Accepted,
            wintrust::Trust::Unsigned => PlatformTrust::Rejected {
                detail: BoundedText::new(UNSIGNED),
            },
            wintrust::Trust::Rejected => PlatformTrust::Rejected {
                detail: BoundedText::new(NOT_TRUSTED),
            },
        };

        // An unsigned image is a developer build, not a broken probe, so the
        // signer stays absent and the read never fails.
        let signer = match digest(&path) {
            Ok(found) => {
                let text = fidelity_cipher::hex(&found);
                let label = label(&text);
                Some(Signer::new(text.into_bytes(), label))
            }
            Err(_) => None,
        };

        Observation::Fact(CodeIdentity::new(trust, signer))
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let pinned = match expected.windows_choice() {
            Some(Choice::Value(thumbprint)) => thumbprint,
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

        let Ok(path) = image::path() else {
            return Observation::failed("the running image named no path");
        };

        // A read that failed is a health finding, and never a difference. The
        // host pinned a value, and a probe that read no certificate has no
        // evidence either way.
        match digest(&path) {
            Ok(found) => Observation::Fact(compare(&found, pinned.as_bytes())),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Compares the signer of the image against the one that the host pinned.
///
/// The comparison is a plain function, so a test proves both answers without
/// a signed image. Only a real release carries one.
fn compare(found: &[u8; 32], pinned: &[u8; 32]) -> IdentityMatch {
    if found == pinned {
        IdentityMatch::Same
    } else {
        IdentityMatch::Different {
            detail: BoundedText::new(ANOTHER_SIGNER),
        }
    }
}

/// The SHA-256 of the certificate that signed this image.
fn digest(path: &[u16]) -> Result<[u8; 32], &'static str> {
    crypt::signer_certificate(path).map(|certificate| fidelity_cipher::sha256(&certificate))
}

/// A short readable form of the signer, for evidence.
fn label(hex: &str) -> String {
    format!("certificate sha256 {}", hex.get(..8).unwrap_or(hex))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Identity, IdentityMatch, Observation, PlatformTrust};
    use fidelity_types::{AuthenticodeThumbprint, Choice, ExpectedIdentity};

    use super::{WindowsEnvironment, compare, label};

    #[test]
    fn an_unsigned_build_reports_no_platform_trust() {
        // The clean control for a developer build. Cargo signs nothing, so the
        // tier must report rather than accept. A build that read as trusted
        // here would accept every repackaged binary.
        let Observation::Fact(identity) = WindowsEnvironment::new().code_identity() else {
            panic!("Windows must report its code identity");
        };
        assert!(matches!(identity.trust(), &PlatformTrust::Rejected { .. }));
    }

    #[test]
    fn an_unsigned_build_names_no_signer() {
        // The other half of the same control. No certificate means no signer,
        // and a signer here would give every guarded constant a wrong key.
        let Observation::Fact(identity) = WindowsEnvironment::new().code_identity() else {
            panic!("Windows must report its code identity");
        };
        assert!(identity.signer().is_none());
    }

    #[test]
    fn a_host_that_states_nothing_reports_unsupported() {
        assert!(matches!(
            WindowsEnvironment::new().identity_match(&ExpectedIdentity::new()),
            Observation::Unsupported { .. }
        ));
    }

    #[test]
    fn an_accepted_gap_reports_unsupported() {
        let expected = ExpectedIdentity::new().windows(Choice::AcceptUnsupported);
        assert!(matches!(
            WindowsEnvironment::new().identity_match(&expected),
            Observation::Unsupported { .. }
        ));
    }

    #[test]
    fn a_pinned_value_against_an_unsigned_image_reports_a_health_finding() {
        // The host pinned a value and the image carries no certificate, so the
        // probe has no evidence either way. That is a failed read, and never
        // a difference, because a difference would report a repackage that
        // nothing observed.
        let expected = ExpectedIdentity::new()
            .windows(Choice::Value(AuthenticodeThumbprint::from_bytes([0; 32])));
        assert!(matches!(
            WindowsEnvironment::new().identity_match(&expected),
            Observation::Failed { .. }
        ));
    }

    #[test]
    fn the_same_certificate_matches() {
        assert_eq!(compare(&[7; 32], &[7; 32]), IdentityMatch::Same);
    }

    #[test]
    fn another_certificate_differs() {
        assert!(matches!(
            compare(&[7; 32], &[9; 32]),
            IdentityMatch::Different { .. }
        ));
    }

    #[test]
    fn the_digest_reads_as_lowercase_hexadecimal() {
        // The form that a build states, and the form that `certutil` prints.
        let mut digest = [0_u8; 32];
        digest[0] = 0xAB;
        digest[31] = 0x0F;
        let text = fidelity_cipher::hex(&digest);
        assert_eq!(text.len(), 64);
        assert!(text.starts_with("ab"));
        assert!(text.ends_with("0f"));
    }

    #[test]
    fn the_label_names_the_first_four_bytes() {
        assert_eq!(label("2b16c14d00000000"), "certificate sha256 2b16c14d");
    }
}
