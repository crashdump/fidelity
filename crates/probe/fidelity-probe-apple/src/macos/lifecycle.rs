//! The lifecycle capability on macOS.
//!
//! iOS prepares its worker the same way, so the body lives in
//! [`common::lifecycle`] and this file binds it to
//! the macOS environment.

use fidelity_core::{Lifecycle, WorkerSetup};

use crate::common;

use super::MacEnvironment;

impl Lifecycle for MacEnvironment {
    fn prepare_worker(&self) -> WorkerSetup {
        common::lifecycle::prepare_worker()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::Lifecycle;

    use super::MacEnvironment;

    #[test]
    fn the_probe_prepares_the_calling_thread() {
        // The call applies to the caller, so the test takes its own thread
        // rather than changing the class of the test runner.
        std::thread::spawn(|| {
            assert!(MacEnvironment::new().prepare_worker().prepared());
        })
        .join()
        .unwrap_or_else(|_| panic!("the test thread must finish"));
    }
}
