//! The lifecycle capability on iOS.
//!
//! macOS prepares its worker the same way, so the body lives in
//! [`common::lifecycle`](crate::common::lifecycle) and this file binds it to
//! the iOS environment.
//!
//! One part of this capability needs no code here, and a measurement says so
//! rather than a reading. A mobile system suspends an application and resumes
//! it later, and `docs/plan/03-runtime-and-api.md` makes a full scan the
//! worker's first work item after a resume. The worker waits between scans with
//! a relative sleep, and the machine leaves the clock running while it holds
//! the process, so that wait expires during the suspension and the next scan
//! runs at once. No notification reaches this file, and none has to.
//!
//! Measured in an iOS 18.4 simulator on 2026-08-19: a freeze of 20 seconds
//! moved no scan, and the first scan after the resume landed 0 ms after it. The
//! control is `tests/platform/controls/resume-after-freeze.sh`, and it holds
//! the process with a signal. A device suspends an application itself, and
//! `tests/platform/README.md` holds that gap.

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
