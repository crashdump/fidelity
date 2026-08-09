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
