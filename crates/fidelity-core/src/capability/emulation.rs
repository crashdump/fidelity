//! The emulation capability, for the `Virtualization` category.

use crate::fact::MachineHost;
use crate::{NO_PROBE, Observation};

/// Reads what the operating system reports about the machine below it.
///
/// The capability takes the answer of the kernel, and not the answer of the
/// processor. The
/// [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes the
/// Windows processor flag as decisive evidence, because that flag also
/// identifies ordinary Hyper-V, WSL2, and Windows Sandbox. A kernel that
/// states its own machine answers the question that the category asks.
///
/// A platform may run a system inside a machine in more than one way. This
/// capability reports one of them, so a platform that gains a second
/// independent source adds a separate detector rather than a second answer
/// here. That is the same rule that [`tracer`](crate::capability::tracer) and
/// [`device`](crate::capability::device) follow.
pub trait Emulation {
    /// What the system reports about the machine that runs it.
    fn machine_host(&self) -> Observation<MachineHost> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
