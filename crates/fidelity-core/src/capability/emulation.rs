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
/// A platform may hold more than one source, and what it does with the second
/// one depends on what the two can prove about each other.
///
/// Two sources that each answer the whole question are independent, and a
/// disagreement between them is itself direct evidence that something answers
/// for the operating system. Such a platform adds a separate detector, so the
/// host sees both answers. [`tracer`](crate::capability::tracer) and
/// [`device`](crate::capability::device) follow that rule.
///
/// Two sources that each cover part of the question are not independent, and
/// this capability reads both. Linux is the case: the firmware names the
/// machine, and a monitor that publishes no firmware identity still needs the
/// paravirtual bus. Neither one states that the other is absent, so the two
/// can never disagree and a second detector would report nothing new.
pub trait Emulation {
    /// What the system reports about the machine that runs it.
    fn machine_host(&self) -> Observation<MachineHost> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
