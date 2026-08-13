use std::sync::{Arc, Mutex, PoisonError};

use fidelity_engine::State;
use fidelity_types::{Category, Snapshot};

use crate::{Denied, denies_until_full_scan, full_scan_complete, latched_categories};

#[derive(Debug)]
pub(crate) struct Runtime {
    /// The worker holds the same state, so the two share one lock.
    state: Arc<Mutex<State>>,

    /// The code identity that the initial scan observed.
    ///
    /// A guarded constant derives its key from these bytes. The value is read
    /// once, because a fresh read costs about 1.3 ms on macOS, which is far
    /// beyond what a guarded read can spend. The worker still re-reads the
    /// identity on every cycle as a detector, so a later change is reported
    /// even though the key stays fixed.
    ///
    /// The slice is empty when the platform reports no signer.
    identity: Box<[u8]>,
}

impl Runtime {
    pub(crate) const fn new(state: Arc<Mutex<State>>, identity: Box<[u8]>) -> Self {
        Self { state, identity }
    }
}

/// A reference to the running Fidelity runtime.
///
/// The handle is cloneable, and every clone refers to the same runtime and
/// the same state. The runtime outlives every handle: it runs until the
/// process stops, there is no public way to stop it, and a dropped handle
/// changes nothing.
///
/// Holding a handle is how a caller proves that the runtime started, so a
/// protected operation cannot run its check before the start succeeded.
#[derive(Debug, Clone)]
pub struct Handle {
    runtime: Arc<Runtime>,
}

impl Handle {
    pub(crate) const fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }

    /// Reports whether a protected operation may run.
    ///
    /// Call this immediately before each protected operation. It reads the
    /// already-latched decision, so it never scans, never allocates, and
    /// never blocks. It is not a fresh scan, it is not an authorization
    /// system, and it is not an atomic boundary around the operation, so a
    /// check-then-use race remains possible.
    ///
    /// The check is safe inside the finding callback, because the runtime
    /// holds no lock while a callback runs.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] when any category latched a denial. Read
    /// [`snapshot`](Handle::snapshot) for the finding that caused it.
    ///
    /// Returns [`DenialReason::IncompleteCoverage`](crate::DenialReason::IncompleteCoverage)
    /// when the host called
    /// [`Builder::deny_until_first_full_scan`](crate::Builder::deny_until_first_full_scan)
    /// and the worker has not finished its first full cycle.
    pub fn ensure_allowed(&self) -> Result<(), Denied> {
        let categories = latched_categories();
        if !categories.is_empty() {
            return Err(Denied::latched(categories));
        }
        if denies_until_full_scan() && !full_scan_complete() {
            return Err(Denied::incomplete_coverage());
        }
        Ok(())
    }

    /// Latches a permanent denial for one category, on the host's judgment.
    ///
    /// A host that reads the snapshot and reaches its own verdict calls this
    /// to make the verdict effective. Fidelity itself never adds weak signals
    /// together, so this is where a host applies the judgment that Fidelity
    /// declines to apply for it.
    ///
    /// The latch behaves exactly as a detector-driven latch: it is permanent,
    /// it is process-wide, and nothing clears it. The call only ever adds a
    /// denial, so it cannot turn protection off. The snapshot keeps a host
    /// latch distinguishable through
    /// [`Snapshot::host_latched_categories`](fidelity_types::Snapshot::host_latched_categories),
    /// because a host latch has no finding behind it.
    ///
    /// The call is safe inside the finding callback.
    pub fn deny(&self, category: Category) {
        // Both latches are written while this guard lives, so the two never
        // disagree. `snapshot()` takes the same lock, so a reader that finds
        // the process-wide word clear cannot yet read the latched state.
        let mut state = self
            .runtime
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.latch_by_host(category);
        crate::latch(category);
    }

    /// Reports whether the worker completed its first full scan.
    ///
    /// The initial scan runs the cheap detectors only, so this stays false
    /// until every detector has run once. It never returns to false.
    ///
    /// A host that gates its own startup on full coverage reads this instead
    /// of calling [`ensure_allowed`](Handle::ensure_allowed) and inspecting
    /// the reason.
    #[must_use]
    pub fn first_full_scan_complete(&self) -> bool {
        full_scan_complete()
    }

    /// The code identity that the initial scan observed.
    ///
    /// [`guarded!`](crate::guarded) reads this. It is not part of the
    /// supported surface, and it carries no compatibility promise. The value
    /// is not a secret: the operating system reports it to anybody who asks.
    #[doc(hidden)]
    #[must_use]
    pub fn code_identity(&self) -> &[u8] {
        &self.runtime.identity
    }

    /// The authoritative bounded state of the runtime.
    ///
    /// A category that reports rather than denies never reaches the callback,
    /// so this is where a host reads it.
    ///
    /// The call is safe inside the finding callback, because the runtime
    /// holds no lock while a callback runs.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        // A poisoned lock means another thread panicked while it held the
        // state. The state stays readable and the runtime must not stop
        // detection, so recover the guard instead of a panic.
        let state = self
            .runtime
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use fidelity_engine::State;
    use fidelity_types::{Category, Detector};

    use super::{Denied, Handle, Runtime};
    use crate::DenialReason;

    const PROBE: Detector = Detector::new(1, "test.handle", Category::Integrity);

    fn handle() -> Handle {
        Handle::new(Arc::new(Runtime::new(
            Arc::new(Mutex::new(State::new(&[PROBE]))),
            Box::new([]),
        )))
    }

    #[test]
    fn a_clean_runtime_allows_a_protected_operation() {
        let _guard = crate::exclusive_test();
        assert!(handle().ensure_allowed().is_ok());
    }

    #[test]
    fn a_snapshot_reports_one_slot_per_detector() {
        assert_eq!(handle().snapshot().detectors().len(), 1);
    }

    #[test]
    fn a_clone_shares_the_same_state() {
        let first = handle();
        let second = first.clone();
        assert_eq!(first.snapshot(), second.snapshot());
    }

    #[test]
    fn a_dropped_clone_leaves_the_original_usable() {
        let first = handle();
        drop(first.clone());
        assert_eq!(first.snapshot().detectors().len(), 1);
    }

    #[test]
    fn a_host_denial_stops_a_protected_operation() {
        let _guard = crate::exclusive_test();
        let handle = handle();
        handle.deny(Category::Debugging);
        let categories = handle
            .ensure_allowed()
            .err()
            .map(|denial| denial.categories());
        assert!(categories.is_some_and(|set| set.contains(Category::Debugging)));
    }

    #[test]
    fn a_host_denial_explains_itself_in_the_snapshot() {
        let _guard = crate::exclusive_test();
        let handle = handle();
        handle.deny(Category::Debugging);
        let snapshot = handle.snapshot();
        assert!(
            snapshot
                .host_latched_categories()
                .contains(Category::Debugging)
        );
    }

    #[test]
    fn the_two_latches_never_disagree() {
        let _guard = crate::exclusive_test();
        let handle = handle();
        handle.deny(Category::UiAbuse);
        // `ensure_allowed()` reads the process-wide word, and `snapshot()`
        // reads the engine. A reader must never see one without the other.
        let from_check = handle
            .ensure_allowed()
            .err()
            .map(|denial| denial.categories());
        assert_eq!(
            from_check,
            Some(handle.snapshot().latched_categories()),
            "the process-wide latch and the engine latch disagree"
        );
    }

    #[test]
    fn a_host_denial_only_ever_adds() {
        let _guard = crate::exclusive_test();
        let handle = handle();
        handle.deny(Category::UiAbuse);
        handle.deny(Category::Integrity);
        let latched = handle.snapshot().latched_categories();
        assert!(latched.contains(Category::UiAbuse));
        assert!(latched.contains(Category::Integrity));
    }

    #[test]
    fn an_opted_in_host_waits_for_full_coverage() {
        let _guard = crate::exclusive_test();
        crate::set_deny_until_full_scan(true);
        let denial = handle().ensure_allowed().err();
        assert_eq!(
            denial.as_ref().map(Denied::reason),
            Some(DenialReason::IncompleteCoverage)
        );
        assert!(denial.is_some_and(|denial| denial.categories().is_empty()));
    }

    #[test]
    fn full_coverage_closes_the_startup_window() {
        let _guard = crate::exclusive_test();
        crate::set_deny_until_full_scan(true);
        crate::mark_full_scan_complete();
        assert!(handle().ensure_allowed().is_ok());
    }

    #[test]
    fn coverage_is_observable_without_a_denial() {
        let _guard = crate::exclusive_test();
        let handle = handle();
        assert!(!handle.first_full_scan_complete());
        crate::mark_full_scan_complete();
        assert!(handle.first_full_scan_complete());
    }

    #[test]
    fn a_host_that_did_not_opt_in_sees_no_startup_window() {
        let _guard = crate::exclusive_test();
        assert!(!crate::full_scan_complete());
        assert!(handle().ensure_allowed().is_ok());
    }

    #[test]
    fn a_latch_outranks_the_startup_window() {
        let _guard = crate::exclusive_test();
        crate::set_deny_until_full_scan(true);
        let handle = handle();
        handle.deny(Category::Integrity);
        let reason = handle.ensure_allowed().err().map(|denial| denial.reason());
        assert_eq!(reason, Some(DenialReason::Latched));
    }
}
