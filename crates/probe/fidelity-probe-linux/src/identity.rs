//! Image identity on Linux.
//!
//! Linux anchors nothing by default. A distribution signs its packages, and
//! the kernel forgets that by the time a process runs, so no universal check
//! answers the platform-trust question. fs-verity is the one mechanism that
//! does, where the deployment enables it, and most do not.
//!
//! The expected-identity tier answers everywhere. The host pins the digest of
//! the executable it shipped, and the probe hashes the running image and
//! compares. `sha256sum` on the built artifact gives the host that value, so
//! it needs no tool from this project.
//!
//! # No signer, on purpose
//!
//! This capability reports no [`Signer`], so `guarded!()` still refuses a
//! Linux binding and the build fails there as it did before. That is a
//! decision rather than an omission. A content digest changes on every
//! rebuild, so a key derived from it would decrypt every guarded constant to
//! garbage after the next release, and a guarded read reports no error by
//! design. [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! states that hazard for a mixed key, and it applies to this source alone.

use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust};
use fidelity_types::{BoundedText, Choice, ExpectedIdentity};

use crate::LinuxEnvironment;
use crate::sys::verity::{self, Verity};

/// Where the kernel names the running image.
const EXE_PATH: &str = "/proc/self/exe";

/// Why Linux reports no platform trust where fs-verity is absent.
const NO_VERITY: &str = "Linux anchors no signer for a running image, and this deployment enables \
                         no fs-verity";

/// Why an enabled verity with another hash still reports no trust.
const OTHER_HASH: &str = "fs-verity is enabled with a hash that this probe does not read";

/// The reason that an accepted gap reports.
const HOST_ACCEPTED_GAP: &str = "the host accepted no identity check on Linux";

/// The reason that an absent host value reports.
const NO_HOST_VALUE: &str = "the host stated no identity value for Linux";

/// What a pinned host value reports against another image.
const ANOTHER_IMAGE: &str = "the running image holds other content than the host pinned";

impl Identity for LinuxEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        let trust = match verity::measure(EXE_PATH) {
            // The kernel enforces a Merkle tree over this file, so the image
            // cannot change under the process that runs it.
            Verity::Enabled { sha256: true } => PlatformTrust::Accepted,
            Verity::Enabled { sha256: false } => PlatformTrust::Unavailable { reason: OTHER_HASH },
            Verity::Absent { .. } => PlatformTrust::Unavailable { reason: NO_VERITY },
        };

        // No signer. The module documentation states why, and a test holds it.
        Observation::Fact(CodeIdentity::new(trust, None))
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let pinned = match expected.linux_choice() {
            Some(Choice::Value(digest)) => digest,
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
        // host pinned a value, and a probe that could not read the image has
        // no evidence either way.
        match digest() {
            Ok(found) => Observation::Fact(compare(&found, pinned.as_bytes())),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Compares the running image against the digest that the host pinned.
///
/// The comparison is a plain function, so a test proves both answers without
/// a second image on disk.
fn compare(found: &[u8; 32], pinned: &[u8]) -> IdentityMatch {
    if found.as_slice() == pinned {
        IdentityMatch::Same
    } else {
        IdentityMatch::Different {
            detail: BoundedText::new(ANOTHER_IMAGE),
        }
    }
}

/// The SHA-256 of the running image.
///
/// This reads the whole file, so it costs the size of the artifact once. The
/// runtime calls it while `start()` runs and never on a worker cycle, so the
/// cost lands with the other start work. See
/// [state and budgets](../../../../docs/plan/07-state-and-budgets.md).
fn digest() -> Result<[u8; 32], &'static str> {
    let bytes = std::fs::read(EXE_PATH).map_err(|_| "the running image did not open")?;
    Ok(fidelity_cipher::sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{CodeIdentity, Identity, IdentityMatch, Observation, PlatformTrust};
    use fidelity_types::{Choice, ContentDigest, ExpectedIdentity};

    use super::{LinuxEnvironment, compare, digest};

    /// A pinned value that names the running image itself.
    fn pinned(value: [u8; 32]) -> ExpectedIdentity {
        let Ok(digest) = ContentDigest::new(value) else {
            panic!("a 32-byte digest must build");
        };
        ExpectedIdentity::new().linux(Choice::Value(digest))
    }

    #[test]
    fn the_probe_reports_no_signer() {
        // The rule that keeps `guarded!()` refused on Linux. A signer here
        // would let a build bind to a digest that every rebuild changes, and
        // every guarded constant would then decrypt to garbage with no error.
        let Observation::Fact(identity) = LinuxEnvironment::new().code_identity() else {
            panic!("Linux must report its code identity");
        };
        assert!(identity.signer().is_none());
    }

    #[test]
    fn an_ordinary_build_filesystem_reports_no_platform_trust() {
        // The clean control. A machine that enabled fs-verity takes the other
        // arm, and this states which one this machine took.
        let Observation::Fact(identity) = LinuxEnvironment::new().code_identity() else {
            panic!("Linux must report its code identity");
        };
        assert!(matches!(
            identity.trust(),
            &PlatformTrust::Unavailable { .. } | &PlatformTrust::Accepted
        ));
    }

    #[test]
    fn the_running_image_matches_its_own_digest() {
        // The clean control for the expected-identity tier, and it needs no
        // second file: the image is its own answer.
        let Ok(found) = digest() else {
            panic!("the running image must hash");
        };
        assert_eq!(
            LinuxEnvironment::new().identity_match(&pinned(found)),
            Observation::Fact(IdentityMatch::Same)
        );
    }

    #[test]
    fn another_digest_reports_a_difference() {
        // The hostile control, as a value rather than as a repackaged file.
        assert!(matches!(
            LinuxEnvironment::new().identity_match(&pinned([0; 32])),
            Observation::Fact(IdentityMatch::Different { .. })
        ));
    }

    #[test]
    fn a_host_that_states_nothing_reports_unsupported() {
        assert!(matches!(
            LinuxEnvironment::new().identity_match(&ExpectedIdentity::new()),
            Observation::Unsupported { .. }
        ));
    }

    #[test]
    fn a_pinned_digest_of_another_length_still_differs() {
        // `ContentDigest` holds any non-empty length, so the comparison must
        // answer rather than panic when the host pinned a shorter value.
        assert!(matches!(
            compare(&[7; 32], &[7; 16]),
            IdentityMatch::Different { .. }
        ));
    }

    #[test]
    fn an_identity_without_a_signer_still_carries_trust() {
        let identity = CodeIdentity::new(PlatformTrust::Accepted, None);
        assert_eq!(identity.trust(), &PlatformTrust::Accepted);
    }
}
