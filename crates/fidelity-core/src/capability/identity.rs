//! The image identity capability, for the `Integrity` category.

use fidelity_types::ExpectedIdentity;

use crate::fact::{CodeIdentity, IdentityMatch};
use crate::{NO_PROBE, Observation};

/// Reads what the operating system reports about the running image.
///
/// The capability has two tiers, and they answer different questions. Platform
/// trust needs no host input, and it states whether a party the machine trusts
/// signed the image. Expected identity compares against a value the host
/// pinned, and it is the only local evidence of a repackaged application.
///
/// A guarded constant derives its key from the signer that
/// [`code_identity`](Identity::code_identity) reports, so a platform that
/// implements this capability also carries the structural path.
pub trait Identity {
    /// What the operating system reports about the running image.
    fn code_identity(&self) -> Observation<CodeIdentity> {
        Observation::Unsupported { reason: NO_PROBE }
    }

    /// Whether the running image satisfies the expected identity.
    ///
    /// The operating system answers this where it can, because it validates
    /// the complete signature. A byte comparison does not.
    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let _ = expected;
        Observation::Unsupported { reason: NO_PROBE }
    }
}
