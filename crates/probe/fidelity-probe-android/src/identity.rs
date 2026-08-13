//! Image identity on Android.
//!
//! Android has no platform-trust tier. Any self-signed certificate is valid
//! there, so the operating system anchors nothing and the tier reports a gap.
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! states that, and it names the SHA-256 of the signing certificate as the
//! expected-identity value.
//!
//! The certificate comes from the archive that the process runs from, and not
//! from `PackageManager`, because that interface needs a `Context`. The
//! boundary in [`sys::apk`](crate::sys::apk) states the whole reason.

use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust, Signer};
use fidelity_types::{BoundedText, Choice, ExpectedIdentity};

use super::AndroidEnvironment;
use crate::sys::apk;

/// Why Android reports no platform trust.
const ANY_CERTIFICATE_IS_VALID: &str = "Android accepts any self-signed certificate, so the \
                                        platform anchors no signer and states no trust";

/// The reason that an accepted gap reports.
const HOST_ACCEPTED_GAP: &str = "the host accepted no identity check on Android";

/// The reason that an absent host value reports.
const NO_HOST_VALUE: &str = "the host stated no identity value for Android";

/// What a pinned host value reports against another certificate.
const ANOTHER_CERTIFICATE: &str =
    "the archive that this process runs from carries another signing certificate";

impl Identity for AndroidEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        let trust = PlatformTrust::Unavailable {
            reason: ANY_CERTIFICATE_IS_VALID,
        };

        // A process that runs from no archive is a shell binary, not a broken
        // application, so the signer stays absent and the read never fails.
        let signer = match digest() {
            Ok(digest) => {
                let text = fidelity_cipher::hex(&digest);
                let label = label(&text);
                Some(Signer::new(text.into_bytes(), label))
            }
            Err(_) => None,
        };

        Observation::Fact(CodeIdentity::new(trust, signer))
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let pinned = match expected.android_choice() {
            Some(Choice::Value(certificate)) => certificate,
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

        // A read that failed is a health finding, and never a difference. The
        // host pinned a value, and a probe that could not read the archive has
        // no evidence either way.
        match digest() {
            Ok(found) => Observation::Fact(compare(&found, pinned.as_bytes())),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Compares the certificate of the archive against the pinned one.
///
/// The comparison is a plain function, so a test proves both answers without
/// an archive. Only a real application maps one.
fn compare(found: &[u8; 32], pinned: &[u8; 32]) -> IdentityMatch {
    if found == pinned {
        IdentityMatch::Same
    } else {
        IdentityMatch::Different {
            detail: BoundedText::new(ANOTHER_CERTIFICATE),
        }
    }
}

/// The SHA-256 of the certificate that signed this archive.
///
/// Android compares this digest, and `hasSigningCertificate` takes the same
/// one, so the value matches what a host reads from its own pipeline.
fn digest() -> Result<[u8; 32], &'static str> {
    apk::signer_certificate().map(|certificate| fidelity_cipher::sha256(&certificate))
}

/// A readable form of the digest, for evidence.
///
/// The label holds the first four bytes only. The whole digest is public, and
/// a short form is what a reader compares against a build record.
fn label(hex: &str) -> String {
    format!("certificate sha256 {}", hex.get(..8).unwrap_or(hex))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Identity, IdentityMatch, Observation, PlatformTrust};
    use fidelity_types::{CertificateSha256, Choice, ExpectedIdentity};

    use super::{AndroidEnvironment, compare, label};

    /// The digest of the recorded test archive, which
    /// `evidence/controls/make-apk.sh` builds and `keytool -list -v` prints.
    const RECORDED: [u8; 32] = [
        0x2b, 0x16, 0xc1, 0x4d, 0x5d, 0xc3, 0x8a, 0x49, 0x58, 0x76, 0x1a, 0xf8, 0xbb, 0x7f, 0xb9,
        0x25, 0xd5, 0xae, 0xea, 0x89, 0x94, 0xba, 0xbf, 0x78, 0x18, 0x5b, 0xb0, 0x04, 0xc2, 0xd3,
        0x83, 0x86,
    ];

    fn pinned(value: [u8; 32]) -> ExpectedIdentity {
        ExpectedIdentity::new().android(Choice::Value(CertificateSha256::from_bytes(value)))
    }

    #[test]
    fn the_probe_reads_its_identity_without_a_failure() {
        let observation = AndroidEnvironment::new().code_identity();
        assert!(matches!(observation, Observation::Fact(_)));
    }

    #[test]
    fn android_reports_no_platform_trust() {
        let Observation::Fact(identity) = AndroidEnvironment::new().code_identity() else {
            unreachable!("the probe reads the fact on any process")
        };
        assert!(matches!(
            identity.trust(),
            PlatformTrust::Unavailable { .. }
        ));
    }

    #[test]
    fn an_absent_host_value_reports_unsupported() {
        let observation = AndroidEnvironment::new().identity_match(&ExpectedIdentity::new());
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn an_accepted_gap_reports_unsupported() {
        let expected = ExpectedIdentity::new().android(Choice::AcceptUnsupported);
        let observation = AndroidEnvironment::new().identity_match(&expected);
        assert!(matches!(observation, Observation::Unsupported { .. }));
    }

    #[test]
    fn a_process_with_no_archive_reports_a_health_finding() {
        // Never a difference. A shell binary maps no archive, so the probe has
        // no evidence either way, and it says so.
        let observation = AndroidEnvironment::new().identity_match(&pinned(RECORDED));
        assert!(
            matches!(observation, Observation::Failed { .. }),
            "{observation:?}"
        );
    }

    #[test]
    fn the_certificate_that_the_host_pinned_reports_a_match() {
        assert_eq!(compare(&RECORDED, &RECORDED), IdentityMatch::Same);
    }

    #[test]
    fn another_certificate_reports_a_difference() {
        let mut other = RECORDED;
        other[0] ^= 0xff;
        assert!(matches!(
            compare(&other, &RECORDED),
            IdentityMatch::Different { .. }
        ));
    }

    #[test]
    fn the_label_states_the_first_bytes_of_the_digest() {
        assert_eq!(
            label(&fidelity_cipher::hex(&RECORDED)),
            "certificate sha256 2b16c14d"
        );
    }

    #[test]
    fn the_raw_digest_is_not_text_that_a_build_could_state() {
        // The rule that `Signer::material` states, and the defect that the
        // hexadecimal form replaced. This probe used to report these 32 bytes.
        // A build names its identity in a variable that carries a string, and
        // no string holds these, so a bound Android build was impossible and
        // every guarded constant decrypted to garbage in silence.
        assert!(String::from_utf8(RECORDED.to_vec()).is_err());
    }

    #[test]
    fn the_material_names_the_whole_digest_as_text() {
        let text = fidelity_cipher::hex(&RECORDED);
        assert_eq!(text.len(), 64);
        assert!(text.starts_with("2b16c14d"), "{text}");
    }
}
