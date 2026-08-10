//! Detectors for the `Integrity` category.
//!
//! The category asks whether executable code, a trusted image, or process
//! state changed unexpectedly. It holds two baselines, and the
//! [plan](../../../../docs/plan/04-detectors-and-platforms.md) defines both.
//! Image identity answers whether this is the expected image. The runtime
//! baseline answers whether the process mapped code after it started. Both
//! have landed.

mod baseline;
mod identity;

pub use baseline::RUNTIME_BASELINE;
pub use identity::{EXPECTED_IDENTITY, PLATFORM_TRUST};

pub(crate) use baseline::runtime_baseline;
pub(crate) use identity::{expected_identity, platform_trust};
