//! The tracer capability, for the `Debugging` category.

use crate::fact::TracerState;
use crate::{NO_PROBE, Observation};

/// Reads what the operating system reports about a tracer on this process.
///
/// The capability reports the state that the kernel holds, and not a timing
/// measurement or an exception trick. The
/// [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes both,
/// because each one destabilizes the host that Fidelity runs inside.
///
/// A platform may offer more than one independent source of this state. A
/// disagreement between two sources is itself evidence, in the same way that
/// the image identity cross-check treats one. This capability reports one
/// state, so a platform that gains a second source adds a separate detector
/// rather than a second answer here.
pub trait Tracer {
    /// Whether a tracer holds this process now.
    fn tracer_state(&self) -> Observation<TracerState> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
