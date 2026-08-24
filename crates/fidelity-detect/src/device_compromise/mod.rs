//! Detectors for the `DeviceCompromise` category.
//!
//! The category asks whether the security model of the operating system still
//! holds. Root and jailbreak are the two names for losing it, and both give an
//! attacker every guarantee that the sandbox and the code-signing rules were
//! supposed to keep.
//!
//! The [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes two
//! mechanisms here. A static path list is not decisive evidence, because it
//! ages with every new tool and names the tool rather than the weakness. Remote
//! attestation does not belong inside the library, because it needs a network
//! and a service, and [ADR-0004](../../../../docs/adr/0004-no-network-in-library.md)
//! keeps both out.
//!
//! What is left is what the system states about itself.

mod system_build;
mod verified_boot;

pub use system_build::SYSTEM_BUILD;
pub use verified_boot::VERIFIED_BOOT;

pub(crate) use system_build::system_build;
pub(crate) use verified_boot::verified_boot;
