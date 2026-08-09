//! The facts that the image identity capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about the trust of the running image.
///
/// This is the platform-trust tier. It needs no host input, and it proves that
/// a party the machine trusts signed the image. It does not prove that the
/// host application signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformTrust {
    /// The operating system validated the image against a trusted anchor.
    Accepted,

    /// The operating system did not validate the image.
    Rejected {
        /// What the operating system reported, in text that holds no
        /// application data.
        detail: BoundedText,
    },

    /// The platform exposes no equivalent check.
    Unavailable {
        /// Why the platform reports no trust status.
        reason: &'static str,
    },
}

/// The signer that the operating system reports for the running image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    material: Vec<u8>,
    label: BoundedText,
}

impl Signer {
    /// Creates a signer from its stable bytes and a readable label.
    #[must_use]
    pub fn new(material: impl Into<Vec<u8>>, label: impl Into<String>) -> Self {
        Self {
            material: material.into(),
            label: BoundedText::new(label),
        }
    }

    /// The stable bytes that name the signer.
    ///
    /// A guarded constant derives its key from these bytes, so a probe must
    /// return the same bytes on every run of the same image. A value that
    /// moves between runs, or between operating-system releases, breaks every
    /// guarded constant in the host and reports no error while it does so.
    ///
    /// The bytes must also be text that a build can state. A build names its
    /// identity in the `FIDELITY_CODE_IDENTITY` variable, which carries a
    /// string, and the expansion takes the bytes of that string. A probe that
    /// returned a raw digest would therefore make the binding impossible on
    /// its platform, and every guarded constant would decrypt to garbage with
    /// no error. A probe that reports a binary value converts it, and each one
    /// has a test that holds that.
    #[must_use]
    pub fn material(&self) -> &[u8] {
        &self.material
    }

    /// A short readable form of the signer, for evidence.
    ///
    /// The label holds no application data.
    #[must_use]
    pub fn label(&self) -> &BoundedText {
        &self.label
    }
}

/// The code identity that the operating system reports for the running image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIdentity {
    trust: PlatformTrust,
    signer: Option<Signer>,
}

impl CodeIdentity {
    /// Creates a code identity from its trust status and its signer.
    #[must_use]
    pub const fn new(trust: PlatformTrust, signer: Option<Signer>) -> Self {
        Self { trust, signer }
    }

    /// What the operating system reports about the trust of the image.
    #[must_use]
    pub const fn trust(&self) -> &PlatformTrust {
        &self.trust
    }

    /// The signer, where the platform names one.
    #[must_use]
    pub const fn signer(&self) -> Option<&Signer> {
        self.signer.as_ref()
    }
}

/// Whether the running image satisfies the identity that the host pinned.
///
/// This is the expected-identity tier. The host supplies the value, because
/// Fidelity never learns it from the running bytes it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityMatch {
    /// The running image satisfies the value that the host supplied.
    Same,

    /// The running image does not satisfy that value.
    Different {
        /// What differs, in text that holds no application data.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use super::{CodeIdentity, PlatformTrust, Signer};

    #[test]
    fn a_signer_keeps_its_material() {
        let signer = Signer::new(*b"ABCDE12345", "team ABCDE12345");
        assert_eq!(signer.material(), b"ABCDE12345");
    }

    #[test]
    fn a_signer_keeps_its_label() {
        let signer = Signer::new(*b"ABCDE12345", "team ABCDE12345");
        assert_eq!(signer.label().text(), "team ABCDE12345");
    }

    #[test]
    fn an_identity_without_a_signer_still_carries_trust() {
        let identity = CodeIdentity::new(PlatformTrust::Accepted, None);
        assert_eq!(identity.trust(), &PlatformTrust::Accepted);
        assert!(identity.signer().is_none());
    }
}
