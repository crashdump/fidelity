//! The dispatch capability, for the `Instrumentation` category.

use crate::fact::DispatchTargets;
use crate::{NO_PROBE, Observation};

/// Reads the dispatch targets of the main image.
///
/// A loader resolves an imported call through a table of pointers. A hook that
/// rewrites one entry redirects the call to code that already exists, so it
/// maps no new executable region and the
/// [runtime baseline](crate::capability::baseline) reports clean. The table
/// holds data rather than code, so no executable-memory rule reaches it
/// either. Measured on Linux and ARM64: a `memcpy` slot redirected to `memmove`
/// leaves the runtime baseline clean, and only a comparison of the table
/// against the start of the process reports it.
///
/// The capability reads the main image alone, because a shared library can
/// hold thousands of targets and the snapshot memory must stay bounded. The
/// main image is the table that an attacker rewrites to intercept the host's
/// own calls.
pub trait Dispatch {
    /// The dispatch targets of the main image.
    fn dispatch_targets(&self) -> Observation<DispatchTargets> {
        Observation::Unsupported { reason: NO_PROBE }
    }
}
