//! The lifecycle capability, which reports no finding.

use crate::fact::WorkerSetup;

/// What the worker thread must do on this platform.
///
/// Every other capability answers a question about the environment, and a
/// detector turns that answer into a finding. This one carries the platform
/// work that the worker itself needs, so it has no category and no detector.
/// It exists so that the engine stays portable: without it the worker would
/// gate on the target, and platform code would leave the probe crates. See
/// `docs/plan/06-delivery.md`.
///
/// The default is [`NothingToDo`](WorkerSetup::NothingToDo) rather than
/// `Unsupported`, and that departs from the pattern that
/// [the module](super) states. The reason is that the two mean the same thing
/// here: a platform that asks nothing of the worker thread has no gap, and a
/// desktop system that schedules an ordinary thread correctly is the common
/// case rather than a missing probe.
pub trait Lifecycle {
    /// Prepares the calling thread for the work that this platform needs.
    ///
    /// The worker calls this once, on its own thread, before its first cycle.
    /// It runs on that thread because the platform work applies to the caller:
    /// Apple sets the quality of service of the calling thread, and Android
    /// attaches the calling thread to the JVM.
    fn prepare_worker(&self) -> WorkerSetup {
        WorkerSetup::NothingToDo
    }
}
