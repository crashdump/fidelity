//! The public data model for Fidelity.
//!
//! Fidelity detects hostile changes to an application's runtime environment.
//! This crate holds the types that the `fidelity` facade re-exports. The
//! facade is the supported entry point, and it alone follows `SemVer`. This
//! crate carries no compatibility promise of its own.
//!
//! `docs/plan/` states the behavior that these types describe. Rustdoc is
//! authoritative for the Rust surface.
//!
//! # Stability of the enumerations
//!
//! [`Category`], [`Evidence`], and the platform list grow after v1, so they
//! are `#[non_exhaustive]`. [`Action`], [`SignalStrength`], and [`Outcome`]
//! stay exhaustive, so the common host match needs no wildcard arm.

#![forbid(unsafe_code)]

mod action;
mod category;
mod detector;
mod evidence;
mod finding;
mod identity;
mod outcome;
mod snapshot;
mod strength;

pub use action::Action;
pub use category::{Category, CategorySet, CategorySetIter};
pub use detector::Detector;
pub use evidence::{BoundedText, Evidence, MAX_EVIDENCE_BYTES};
pub use finding::Finding;
pub use identity::{
    AuthenticodeThumbprint, CertificateSha256, Choice, CodeRequirement, ContentDigest,
    ExpectedIdentity, IdentityError, Platform, TeamIdentifier,
};
pub use outcome::Outcome;
pub use snapshot::{DetectorState, Snapshot};
pub use strength::SignalStrength;

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    //! The optional feature states that a host can export a finding. These
    //! tests prove that every type a report reaches carries the bound, and
    //! they add no format crate to do it: a value that satisfies `Serialize`
    //! is what the feature promises, and the encoding is the host's choice.

    use crate::{
        Action, BoundedText, Category, CategorySet, Detector, DetectorState, Evidence, Finding,
        Outcome, Platform, SignalStrength, Snapshot,
    };

    const fn exports<T: serde::Serialize>() {}

    #[test]
    fn every_type_that_a_report_reaches_can_be_exported() {
        exports::<Snapshot>();
        exports::<DetectorState>();
        exports::<Outcome>();
        exports::<Finding>();
        exports::<Evidence>();
        exports::<BoundedText>();
        exports::<Detector>();
        exports::<Category>();
        exports::<CategorySet>();
        exports::<SignalStrength>();
        exports::<Action>();
        exports::<Platform>();
    }
}
