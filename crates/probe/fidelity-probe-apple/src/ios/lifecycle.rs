//! The lifecycle capability on iOS.
//!
//! macOS prepares its worker the same way, so the body lives in
//! [`common::lifecycle`](crate::common::lifecycle) and this file binds it to
//! the iOS environment.
//!
//! One part of this capability is still absent here. A mobile system suspends
//! an application and resumes it later, and
//! `docs/plan/03-runtime-and-api.md` makes a full scan the worker's first work
//! item after a resume. That needs an application lifecycle notification, so it
//! arrives with an application harness that can produce one.

use fidelity_core::{Lifecycle, WorkerSetup};

use crate::common;

use super::IosEnvironment;

impl Lifecycle for IosEnvironment {
    fn prepare_worker(&self) -> WorkerSetup {
        common::lifecycle::prepare_worker()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::Lifecycle;

    use super::IosEnvironment;

    #[test]
    fn the_probe_prepares_the_calling_thread() {
        // The call applies to the caller, so the test takes its own thread
        // rather than changing the class of the test runner.
        std::thread::spawn(|| {
            assert!(IosEnvironment::new().prepare_worker().prepared());
        })
        .join()
        .unwrap_or_else(|_| panic!("the test thread must finish"));
    }
}
