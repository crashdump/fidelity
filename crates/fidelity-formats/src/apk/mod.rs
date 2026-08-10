//! Readers for the archive that Android runs an application from.
//!
//! Android reports the signing certificate through `PackageManager`, and that
//! interface needs a `Context`. A probe cannot reach one without a hidden
//! interface or a new public field, and
//! [delivery](../../../docs/plan/06-delivery.md) refuses both. The process
//! maps its own archive, so the signature that the archive already carries is
//! the route that stays inside the rules.
//!
//! The readers here take bytes and return bytes. They never open a file, and
//! they never hash: the probe reads the two ranges that [`zip`] names, and the
//! capability hashes the certificate that [`signing`] returns.
//!
//! Every value here is little-endian, which is what the archive format states.
//! The Mach-O readers next door are big-endian, so the two never share a
//! helper.

pub mod signing;
pub mod zip;
