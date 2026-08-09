//! The device capability, for the `DeviceCompromise` category.

use crate::fact::SystemBuild;
use crate::{NO_PROBE, Observation};

/// Reads what the operating system reports about its own build.
///
/// The capability reports what the system states about itself, and not the
/// presence of a file, a package, or a command. The
/// [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes a
/// static path list as decisive evidence, because a path list ages, and it
/// names a tool rather than the weakness that the tool needs.
///
/// A platform may weaken its security model in more than one way. This
/// capability reports one of them, so a platform that gains a second
/// independent source adds a separate detector rather than a second answer
/// here. That is the same rule that [`tracer`](crate::capability::tracer)
/// follows.
pub trait Device {
    /// What the system reports about the build that runs now.
    fn system_build(&self) -> Observation<SystemBuild> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
