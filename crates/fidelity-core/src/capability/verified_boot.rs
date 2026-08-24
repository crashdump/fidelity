//! The Android Verified Boot capability.

use crate::fact::BootVerification;
use crate::{NO_PROBE, Observation};

/// Reads the Android Verified Boot state.
///
/// This capability stays separate from the system-build capability. Each one
/// reads an independent system statement and supplies a separate detector.
pub trait VerifiedBoot {
    /// What Android reports about boot verification and the bootloader lock.
    fn boot_verification(&self) -> Observation<BootVerification> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
