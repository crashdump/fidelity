//! The normalized facts that probes report.
//!
//! A fact says what the operating system reported. It carries no judgement, no
//! strength, and no response: a detector adds those. Every platform maps its
//! own interface onto these types, so a detector stays portable and testable.
//!
//! One module per capability, named as the capability is named in
//! [`capability`](crate::capability).

pub mod baseline;
pub mod device;
pub mod emulation;
pub mod identity;
pub mod injection;
pub mod lifecycle;
pub mod tracer;

pub use baseline::{CodeRegions, MAX_REGIONS, Region};
pub use device::SystemBuild;
pub use emulation::MachineHost;
pub use identity::{CodeIdentity, IdentityMatch, PlatformTrust, Signer};
pub use injection::CodeOrigin;
pub use lifecycle::WorkerSetup;
pub use tracer::TracerState;
