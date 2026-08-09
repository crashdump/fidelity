//! The injection capability, for the `Instrumentation` category.

use crate::fact::CodeOrigin;
use crate::{NO_PROBE, Observation};

/// Reads what the operating system reports about the code in this process.
///
/// The capability reports structural evidence, and never a tool name or a
/// port. The [plan](../../../../docs/plan/04-detectors-and-platforms.md)
/// excludes both, because a name is trivial to change.
///
/// A run-time compiler generates code that no file accounts for, so the probe
/// must separate a region that the kernel named from a region that nobody
/// named. Measured on Android: a runtime names its code cache, so the two are
/// distinguishable.
pub trait Injection {
    /// Whether a file accounts for every executable region.
    fn code_origin(&self) -> Observation<CodeOrigin> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
