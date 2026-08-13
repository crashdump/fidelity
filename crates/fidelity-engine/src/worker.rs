use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fidelity_core::{Environment, WorkerSetup};
use fidelity_detect::Detectors;
use fidelity_types::{
    Action, BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength,
};

use crate::{Policy, State};

/// The host callback that a qualifying finding invokes.
pub type Callback = Box<dyn FnMut(&Finding) + Send + 'static>;

/// The time between two full scans, before jitter.
const CYCLE: Duration = Duration::from_secs(5);

/// The share of the cycle that jitter may add.
///
/// Jitter stops a scan from landing on a schedule that an attacker can predict
/// and step around.
const JITTER_PERCENT: u64 = 40;

/// The process-wide state that the facade owns, as function pointers.
///
/// The denial latch and the coverage flag live in the `fidelity` facade,
/// because that is the layer that holds the one-runtime rule. An isolated test
/// runtime passes hooks that change nothing, so it stays independent of the
/// process.
#[derive(Debug, Clone, Copy)]
pub struct Hooks {
    /// Latches a process-wide denial for one category.
    pub latch: fn(Category),

    /// Records that the first full scan finished.
    pub full_scan_complete: fn(),
}

impl Hooks {
    /// Creates hooks that change no process-wide state.
    #[must_use]
    pub const fn detached() -> Self {
        Self {
            latch: |_| {},
            full_scan_complete: || {},
        }
    }
}

/// The wall-clock time, in milliseconds since the Unix epoch.
///
/// The value is informational, and it may move backwards. A clock before the
/// epoch reports zero rather than a panic.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Records scan outcomes, and latches every qualifying denial.
///
/// The caller applies the returned actions afterwards. The synchronous initial
/// scan uses this and leaves the actions to the worker, so `start()` returns
/// before a callback runs and before a `Crash` stops the process. A `Deny`
/// latch is active as soon as the call returns.
///
/// The engine latch and the process-wide latch are written under one lock, so
/// the two never disagree. A host that sees a denial always reads a snapshot
/// that explains it, and a snapshot that shows a latch always denies.
pub fn record(
    state: &Mutex<State>,
    policy: &Policy,
    hooks: Hooks,
    outcomes: Vec<(Detector, Outcome)>,
) -> Vec<(Finding, Action)> {
    let mut qualified = Vec::new();
    {
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut denied = Vec::new();
        for (detector, outcome) in outcomes {
            let Some(finding) = state.record(detector, outcome) else {
                continue;
            };
            let Some(action) = policy.qualifying_action(&finding) else {
                continue;
            };
            if action == Action::Deny {
                state.latch(finding.category());
                denied.push(finding.category());
            }
            qualified.push((finding, action));
        }

        // Both latches are written while this lock is held, so no reader ever
        // sees one without the other. `snapshot()` takes this same lock, and
        // `ensure_allowed()` reads the process-wide word alone: a reader that
        // finds that word clear cannot reach the state until this scope ends.
        // The hook writes one atomic word and takes no lock of its own, so it
        // is safe to call here.
        for category in denied {
            (hooks.latch)(category);
        }
    }

    qualified
}

/// The library-owned worker.
///
/// The worker runs until the process stops. It applies every qualifying action
/// from the initial scan as its first work item, then it runs full scans on an
/// internal schedule.
pub struct Worker {
    state: Arc<Mutex<State>>,
    policy: Policy,
    detectors: Detectors,
    environment: Box<dyn Environment>,
    callback: Option<Callback>,
    hooks: Hooks,
    jitter: u64,
    cycle: Duration,
}

impl core::fmt::Debug for Worker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Worker")
            .field("policy", &self.policy)
            .field("detectors", &self.detectors)
            .field("callback", &self.callback.is_some())
            .field("cycle", &self.cycle)
            .finish_non_exhaustive()
    }
}

impl Worker {
    /// Creates a worker for one runtime.
    #[must_use]
    pub fn new(
        state: Arc<Mutex<State>>,
        policy: Policy,
        detectors: Detectors,
        environment: Box<dyn Environment>,
        callback: Option<Callback>,
        hooks: Hooks,
    ) -> Self {
        Self {
            state,
            policy,
            detectors,
            environment,
            callback,
            hooks,
            jitter: now_unix_ms() | 1,
            cycle: CYCLE,
        }
    }

    /// Sets the time between two full scans.
    ///
    /// There is no public interval setting. A deterministic test uses this to
    /// keep its run short.
    #[must_use]
    pub const fn with_cycle(mut self, cycle: Duration) -> Self {
        self.cycle = cycle;
        self
    }

    /// Applies the actions of the initial scan, then runs until the process
    /// stops.
    ///
    /// The caller runs this on the worker thread. It never returns, except
    /// when a `Crash` action stops the process.
    pub fn run(mut self, initial: Vec<(Finding, Action)>) {
        // The platform prepares this thread before it does any work. Apple
        // gives it a quality of service, and Android attaches it to the JVM.
        // Both apply to the calling thread, so neither can run at `start()`.
        // A failure degrades the worker and never stops it, because a worker
        // that refused to run would trade all detection for a preference.
        // Nothing reads the answer yet: it belongs in a diagnostic message, and
        // the workspace holds no dependency that emits one.
        let _setup = self.prepare();

        // `start()` recorded the initial outcomes and latched every qualifying
        // denial before it returned. The worker applies the remaining actions
        // here, so a `Crash` stops the process immediately after the host
        // holds a handle.
        self.dispatch(initial);

        loop {
            let outcomes = self.detectors.scan_all(&*self.environment, now_unix_ms());
            self.apply(outcomes);
            (self.hooks.full_scan_complete)();
            std::thread::sleep(self.next_wait());
        }
    }

    /// Lets the platform prepare this thread.
    ///
    /// The result reaches no detector and no category. The lifecycle
    /// capability describes what Fidelity did to itself, and a finding
    /// describes the environment, so the two never mix.
    #[must_use]
    pub fn prepare(&self) -> WorkerSetup {
        self.environment.prepare_worker()
    }

    /// Runs one cycle, for a test that must not loop.
    pub fn run_once(&mut self) {
        let outcomes = self.detectors.scan_all(&*self.environment, now_unix_ms());
        self.apply(outcomes);
        (self.hooks.full_scan_complete)();
    }

    /// Records the outcomes, then applies every qualifying action.
    fn apply(&mut self, outcomes: Vec<(Detector, Outcome)>) {
        let qualified = record(&self.state, &self.policy, self.hooks, outcomes);
        self.dispatch(qualified);
    }

    /// Applies actions that a caller already recorded and latched.
    ///
    /// The worker holds no lock here, so a callback may read the state.
    fn dispatch(&mut self, qualified: Vec<(Finding, Action)>) {
        for (finding, action) in qualified {
            match action {
                // A denial latched before this point, so both cases are done.
                Action::Report | Action::Deny => {}
                Action::Callback => self.invoke(&finding),
                // The recorded state is authoritative, and the process stops
                // without an unwind and without cleanup.
                Action::Crash => std::process::abort(),
            }
        }
    }

    /// Invokes the host callback, and survives a panic inside it.
    ///
    /// A panic in host code must not stop detection, so the worker records a
    /// `Low` detector-health finding and continues. Under `panic = "abort"`
    /// the process stops instead, because the host selected that strategy.
    fn invoke(&mut self, finding: &Finding) {
        let Some(callback) = self.callback.as_mut() else {
            return;
        };
        let result = catch_unwind(AssertUnwindSafe(|| callback(finding)));
        if result.is_err() {
            let health = Outcome::Finding(Finding::new(
                finding.detector(),
                SignalStrength::Low,
                Evidence::DetectorHealth {
                    detail: BoundedText::new("the host callback panicked"),
                },
                now_unix_ms(),
            ));
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(finding.detector(), health);
        }
    }

    /// The time to wait before the next full scan.
    fn next_wait(&mut self) -> Duration {
        // An xorshift keeps the jitter dependency-free. It selects a delay,
        // not a key, so it needs no cryptographic quality.
        self.jitter ^= self.jitter << 13;
        self.jitter ^= self.jitter >> 7;
        self.jitter ^= self.jitter << 17;
        let millis = u64::try_from(self.cycle.as_millis()).unwrap_or(u64::MAX);
        let span = millis / 100 * JITTER_PERCENT;
        let extra = if span == 0 { 0 } else { self.jitter % span };
        self.cycle + Duration::from_millis(extra)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use fidelity_core::{
        Baseline, Device, Environment, Identity, IdentityMatch, Injection, Lifecycle, Observation,
        Tracer, TracerState, WorkerSetup,
    };
    use fidelity_detect::{
        Detectors, EXPECTED_IDENTITY, INVENTORY, PLATFORM_TRUST, TRACER_PRESENT,
    };
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{
        Action, BoundedText, Category, Choice, CodeRequirement, ExpectedIdentity, IdentityError,
        Outcome, Platform, SignalStrength,
    };

    use super::{Hooks, Worker};
    use crate::{Policy, State};

    fn locked(state: &Arc<Mutex<State>>) -> MutexGuard<'_, State> {
        state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    static LATCHED: AtomicU32 = AtomicU32::new(0);
    static COVERED: AtomicU32 = AtomicU32::new(0);

    fn repackaged() -> Result<(FakeEnvironment, ExpectedIdentity), IdentityError> {
        let environment = FakeEnvironment::new().with_identity_match(Observation::Fact(
            IdentityMatch::Different {
                detail: BoundedText::new("the requirement did not match"),
            },
        ));
        let expected = ExpectedIdentity::new()
            .macos(Choice::Value(CodeRequirement::new("anchor apple generic")?));
        Ok((environment, expected))
    }

    fn worker(
        state: &Arc<Mutex<State>>,
        policy: Policy,
        environment: FakeEnvironment,
        expected: Option<ExpectedIdentity>,
        hooks: Hooks,
    ) -> Worker {
        Worker::new(
            Arc::clone(state),
            policy,
            Detectors::new(expected, None),
            Box::new(environment),
            None,
            hooks,
        )
        .with_cycle(Duration::from_millis(1))
    }

    #[test]
    fn a_cycle_replaces_the_absence_of_coverage() -> Result<(), IdentityError> {
        let (environment, expected) = repackaged()?;
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        worker(
            &state,
            Policy::new(),
            environment,
            Some(expected),
            Hooks::detached(),
        )
        .run_once();

        let snapshot = locked(&state).snapshot();
        let ran = snapshot
            .detector_state(EXPECTED_IDENTITY)
            .is_some_and(|slot| slot.outcome().ran());
        assert!(ran, "the scan must reach the detector");
        Ok(())
    }

    #[test]
    fn a_report_action_latches_nothing() -> Result<(), IdentityError> {
        let (environment, expected) = repackaged()?;
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        worker(
            &state,
            Policy::new(),
            environment,
            Some(expected),
            Hooks::detached(),
        )
        .run_once();

        let latched = locked(&state).latched();
        assert!(latched.is_empty(), "Report must publish and keep running");
        Ok(())
    }

    #[test]
    fn a_deny_action_latches_the_category() -> Result<(), IdentityError> {
        let (environment, expected) = repackaged()?;
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut policy = Policy::new();
        policy.set(Category::Integrity, Action::Deny, SignalStrength::High);

        LATCHED.store(0, Ordering::Release);
        let hooks = Hooks {
            latch: |_| {
                LATCHED.fetch_add(1, Ordering::AcqRel);
            },
            full_scan_complete: || {},
        };
        worker(&state, policy, environment, Some(expected), hooks).run_once();

        let latched = locked(&state).latched();
        assert!(latched.contains(Category::Integrity), "the engine latch");
        assert_eq!(LATCHED.load(Ordering::Acquire), 1, "the facade latch");
        Ok(())
    }

    #[test]
    fn a_finding_below_the_threshold_latches_nothing() {
        // The platform-trust rejection is `Medium`, so a `High` threshold
        // leaves it below the line.
        let environment = FakeEnvironment::new();
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut policy = Policy::new();
        policy.set(Category::Integrity, Action::Deny, SignalStrength::High);
        worker(&state, policy, environment, None, Hooks::detached()).run_once();

        let latched = locked(&state).latched();
        assert!(latched.is_empty());
    }

    #[test]
    fn a_cycle_reports_full_coverage() {
        COVERED.store(0, Ordering::Release);
        let hooks = Hooks {
            latch: |_| {},
            full_scan_complete: || {
                COVERED.fetch_add(1, Ordering::AcqRel);
            },
        };
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        worker(&state, Policy::new(), FakeEnvironment::new(), None, hooks).run_once();
        assert_eq!(COVERED.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_panic_in_the_callback_leaves_the_worker_alive() -> Result<(), IdentityError> {
        let (environment, expected) = repackaged()?;
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut policy = Policy::new();
        policy.set(Category::Integrity, Action::Callback, SignalStrength::High);

        let mut worker = Worker::new(
            Arc::clone(&state),
            policy,
            Detectors::new(Some(expected), None),
            Box::new(environment),
            Some(Box::new(|_| panic!("the host callback fails"))),
            Hooks::detached(),
        );
        worker.run_once();
        // The second cycle proves that the worker survived the first.
        worker.run_once();

        let snapshot = locked(&state).snapshot();
        let recorded = snapshot
            .detector_state(EXPECTED_IDENTITY)
            .is_some_and(|slot| {
                matches!(slot.outcome(), Outcome::Finding(finding)
                if finding.evidence().is_detector_health())
            });
        assert!(recorded, "a callback panic records a health finding");
        Ok(())
    }

    #[test]
    fn the_callback_reads_a_latched_state() -> Result<(), IdentityError> {
        // The runtime holds no lock while a callback runs, so a callback that
        // reads the state must not deadlock.
        let (environment, expected) = repackaged()?;
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut policy = Policy::new();
        policy.set(Category::Integrity, Action::Callback, SignalStrength::High);

        let seen = Arc::new(Mutex::new(0_usize));
        let reader = Arc::clone(&state);
        let counter = Arc::clone(&seen);
        Worker::new(
            Arc::clone(&state),
            policy,
            Detectors::new(Some(expected), None),
            Box::new(environment),
            Some(Box::new(move |_| {
                let snapshot = reader
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .snapshot();
                *counter.lock().unwrap_or_else(PoisonError::into_inner) =
                    snapshot.detectors().len();
            })),
            Hooks::detached(),
        )
        .run_once();

        let observed = *seen.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(observed, INVENTORY.len());
        Ok(())
    }

    #[test]
    fn the_wait_stays_inside_the_jitter_band() {
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut worker = worker(
            &state,
            Policy::new(),
            FakeEnvironment::new(),
            None,
            Hooks::detached(),
        )
        .with_cycle(Duration::from_secs(10));
        for _ in 0..1_000 {
            let wait = worker.next_wait();
            assert!(wait >= Duration::from_secs(10));
            assert!(wait <= Duration::from_secs(14));
        }
    }

    /// How many times a worker asked this environment to prepare its thread.
    static PREPARED: AtomicU32 = AtomicU32::new(0);

    /// An environment that answers nothing, and counts one lifecycle call.
    ///
    /// `FakeEnvironment` states facts, and the worker owns its environment, so
    /// a test cannot read a counter back out of the box. This states the one
    /// thing the rule below needs.
    #[derive(Debug)]
    struct Counting;

    impl Identity for Counting {}
    impl Tracer for Counting {}
    impl Injection for Counting {}
    impl Baseline for Counting {}

    impl Device for Counting {}

    impl Lifecycle for Counting {
        fn prepare_worker(&self) -> WorkerSetup {
            PREPARED.fetch_add(1, Ordering::AcqRel);
            WorkerSetup::NothingToDo
        }
    }

    impl Environment for Counting {
        fn platform(&self) -> Platform {
            Platform::Linux
        }
    }

    #[test]
    fn the_worker_lets_the_platform_prepare_its_thread() {
        // The lifecycle capability reports no finding, so no snapshot shows
        // this. Without the rule a probe could implement `prepare_worker`, the
        // engine could never call it, and every other test would still pass.
        PREPARED.store(0, Ordering::Release);
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let worker = Worker::new(
            Arc::clone(&state),
            Policy::new(),
            Detectors::new(None, None),
            Box::new(Counting),
            None,
            Hooks::detached(),
        );

        assert_eq!(
            PREPARED.load(Ordering::Acquire),
            0,
            "creating a worker prepares no thread"
        );
        assert_eq!(worker.prepare(), WorkerSetup::NothingToDo);
        assert_eq!(PREPARED.load(Ordering::Acquire), 1);
    }

    #[test]
    fn an_unknown_detector_never_reaches_the_state() {
        // `PLATFORM_TRUST` must stay in the inventory, because a state built
        // without it would silently drop every outcome that it reports.
        assert!(INVENTORY.contains(&PLATFORM_TRUST));
    }
    #[test]
    fn a_later_cycle_records_a_change_that_the_first_cycle_missed() {
        // The worker exists to notice a change after start. Every other test
        // here states one fixed environment, so none of them proves it.
        let environment = FakeEnvironment::new().with_tracer_sequence(vec![
            Observation::Fact(TracerState::Absent),
            Observation::Fact(TracerState::Present {
                detail: BoundedText::new("a tracer attached after start"),
            }),
        ]);
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut worker = worker(&state, Policy::new(), environment, None, Hooks::detached());

        worker.run_once();
        let clean = locked(&state)
            .snapshot()
            .detector_state(TRACER_PRESENT)
            .map(|slot| slot.outcome().clone());
        assert_eq!(
            clean,
            Some(Outcome::Clean),
            "the first cycle sees no tracer"
        );

        worker.run_once();
        let found = locked(&state)
            .snapshot()
            .detector_state(TRACER_PRESENT)
            .is_some_and(|slot| matches!(slot.outcome(), Outcome::Finding(_)));
        assert!(found, "the second cycle must record the tracer");
    }

    #[test]
    fn a_change_after_the_first_cycle_latches_a_denial() {
        // The latch is what the host acts on, so the change has to reach it and
        // not only the detector state.
        let environment = FakeEnvironment::new().with_tracer_sequence(vec![
            Observation::Fact(TracerState::Absent),
            Observation::Fact(TracerState::Present {
                detail: BoundedText::new("a tracer attached after start"),
            }),
        ]);
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut policy = Policy::new();
        policy.set(Category::Debugging, Action::Deny, SignalStrength::Medium);
        let mut worker = worker(&state, policy, environment, None, Hooks::detached());

        worker.run_once();
        assert!(
            locked(&state).latched().is_empty(),
            "a clean first cycle latches nothing"
        );

        worker.run_once();
        assert!(
            locked(&state).latched().contains(Category::Debugging),
            "the tracer that attached later must latch the denial"
        );
    }

    #[test]
    fn a_tracer_that_detaches_stays_in_the_report() {
        // The security model states that a finding is permanent history. A
        // recovery makes the detector healthy again and removes nothing.
        let environment = FakeEnvironment::new().with_tracer_sequence(vec![
            Observation::Fact(TracerState::Present {
                detail: BoundedText::new("a tracer held the process"),
            }),
            Observation::Fact(TracerState::Absent),
        ]);
        let state = Arc::new(Mutex::new(State::new(INVENTORY)));
        let mut worker = worker(&state, Policy::new(), environment, None, Hooks::detached());

        worker.run_once();
        worker.run_once();

        let snapshot = locked(&state).snapshot();
        let slot = snapshot.detector_state(TRACER_PRESENT);
        assert!(
            slot.is_some_and(|slot| slot.strongest().is_some()),
            "the detached tracer must stay in the strongest-ever finding"
        );
    }
}
