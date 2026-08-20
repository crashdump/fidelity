//! The dispatch capability, for the `Instrumentation` category.

use crate::fact::DispatchTargets;
use crate::{NO_PROBE, Observation};

/// Reads the dispatch targets of the image of the host.
///
/// A loader resolves an imported call through a table of pointers. A hook that
/// rewrites one entry redirects the call to code that already exists, so it
/// maps no new executable region and the
/// [runtime baseline](crate::capability::baseline) reports clean. The table
/// holds data rather than code, so no executable-memory rule reaches it
/// either. Measured on Linux and ARM64: a redirected `memcpy` slot leaves the
/// runtime baseline clean, and only a comparison of the table against the
/// start of the process reports it.
///
/// The capability reads one image, and that image is the one that holds the
/// code of the host. It reads one alone, because a shared library can hold
/// thousands of targets and the snapshot memory must stay bounded, and that
/// one is the table an attacker rewrites to intercept the calls of the host.
/// Four platforms link the host into the main image and read that. Android
/// reads the library that holds the host, because an application forks from
/// zygote and its main image is a system binary that every application shares.
pub trait Dispatch {
    /// The dispatch targets of the main image.
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
