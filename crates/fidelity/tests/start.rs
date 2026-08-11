//! The started runtime, against the real platform backend.
//!
//! One runtime runs per process and it never stops, so this file holds one
//! test. A second test in the same binary would meet a runtime that the first
//! one started, and it would read that runtime's configuration.
//!
//! The test asserts the lifecycle contract only. It never asserts that a
//! detector found nothing, because the result depends on how the machine
//! signed this test binary. Detector behavior belongs to the probe tests.

use fidelity::{Category, Outcome, StartError};

#[test]
fn the_runtime_starts_once_and_reports_its_state() {
    let handle = match fidelity::new().start() {
        Ok(handle) => handle,
        // A target with no probe crate says so, and says nothing else.
        Err(StartError::PlatformUnavailable { .. }) => return,
        Err(error) => panic!("the start failed: {error}"),
    };

    // The initial scan reached every cheap detector, so no slot reports the
    // absence of coverage.
    let snapshot = handle.snapshot();
    assert!(
        !snapshot.detectors().is_empty(),
        "a started runtime holds one slot for each built-in detector"
    );
    for state in snapshot.detectors() {
        assert_ne!(
            state.outcome(),
            &Outcome::NotRun,
            "the initial scan skipped {}",
            state.detector().name()
        );
    }

    // The default policy reports and never denies, whatever the scan found.
    assert!(
        handle.ensure_allowed().is_ok(),
        "the default policy must not deny a protected operation"
    );

    // A second start meets the runtime that the first one owns.
    assert_eq!(
        fidelity::new().start().err(),
        Some(StartError::AlreadyRunning)
    );

    // A clone refers to the same runtime.
    assert_eq!(handle.clone().snapshot(), snapshot);

    // A host verdict latches, and it stays distinguishable from a detector
    // verdict, because it carries no finding.
    handle.deny(Category::Debugging);
    assert!(handle.ensure_allowed().is_err());
    assert!(
        handle
            .snapshot()
            .host_latched_categories()
            .contains(Category::Debugging)
    );

    // Dropping a handle changes nothing, because the runtime outlives it.
    drop(handle);
    assert_eq!(
        fidelity::new().start().err(),
        Some(StartError::AlreadyRunning)
    );
}
