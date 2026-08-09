//! The runtime baseline capability, for the `Integrity` category.

use crate::fact::CodeRegions;
use crate::{NO_PROBE, Observation};

/// Reads the executable regions that the process maps now.
///
/// `start()` captures one snapshot, and every later scan captures another. A
/// detector compares the two. The capability itself holds no state, so a probe
/// stays a reader of the operating system.
///
/// The comparison answers a question that no absolute rule can. Measured on
/// macOS: a clean process holds gigabytes of executable memory that no file
/// and no image accounts for, so only a change against the start of the
/// process separates injected code from the shared cache.
pub trait Baseline {
    /// The executable regions that the process maps now.
    fn code_regions(&self) -> Observation<CodeRegions> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
