use core::fmt;
use std::sync::{Arc, Mutex};

use fidelity_core::{Environment, Observation};
use fidelity_detect::Detectors;
use fidelity_engine::{Hooks, Policy, State, Worker, now_unix_ms};
use fidelity_types::{Action, Category, ExpectedIdentity, Finding, Platform, SignalStrength};

use crate::handle::Runtime;
use crate::{Handle, StartError, claim_slot, release_slot, set_deny_until_full_scan};

/// The host callback that the runtime invokes on a qualifying finding.
///
/// The runtime moves the callback onto its worker and calls it from that one
/// thread, so it needs no shared-reference bound.
type Callback = Box<dyn FnMut(&Finding) + Send + 'static>;

/// Configures a Fidelity runtime, and starts it.
///
/// [`start`](Builder::start) consumes the builder, so the configuration
/// cannot change afterwards. Every category begins at [`Action::Report`] with
/// a [`SignalStrength::High`] threshold, so an empty builder is a complete
/// configuration.
///
/// Each category takes one setter that carries its action and its threshold
/// together, because the two are one risk decision.
///
/// # Examples
///
/// One runtime runs per process, so this example compiles without a run.
///
/// ```no_run
/// use fidelity::{Action, SignalStrength};
///
/// let handle = fidelity::new()
///     .integrity(Action::Crash, SignalStrength::High)
///     .instrumentation(Action::Deny, SignalStrength::Medium)
///     .start()?;
/// # Ok::<(), fidelity::StartError>(())
/// ```
#[derive(Default)]
pub struct Builder {
    policy: Policy,
    identity: Option<ExpectedIdentity>,
    callback: Option<Callback>,
    deny_until_full_scan: bool,
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder")
            .field("policy", &self.policy)
            .field("identity", &self.identity)
            .field("callback", &self.callback.is_some())
            .field("deny_until_full_scan", &self.deny_until_full_scan)
            .finish()
    }
}

macro_rules! category_setter {
    ($name:ident, $category:ident, $what:literal) => {
        #[doc = concat!("Sets the action and the threshold for ", $what, ".")]
        #[must_use]
        pub fn $name(mut self, action: Action, threshold: SignalStrength) -> Self {
            self.policy.set(Category::$category, action, threshold);
            self
        }
    };
}

impl Builder {
    category_setter!(
        integrity,
        Integrity,
        "modified code, image, or process state"
    );
    category_setter!(debugging, Debugging, "a debugger or a tracer");
    category_setter!(
        instrumentation,
        Instrumentation,
        "a hook, an injection, or dynamic instrumentation"
    );
    category_setter!(
        device_compromise,
        DeviceCompromise,
        "root, jailbreak, or an equivalent compromise"
    );
    category_setter!(
        virtualization,
        Virtualization,
        "an emulator, a virtual machine, or an analysis environment"
    );
    category_setter!(
        ui_abuse,
        UiAbuse,
        "another application that reads or drives the user interface"
    );

    /// Supplies the expected identity values, for every target at once.
    ///
    /// One call covers every platform, so the configuration cross-compiles.
    /// The call also makes the identity check required: the start fails when
    /// the value states no choice for the target platform.
    #[must_use]
    pub fn expected_identity(mut self, identity: ExpectedIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Denies every protected operation until the first full scan completes.
    ///
    /// The initial scan runs the cheap detectors only, so root, jailbreak,
    /// emulator, and UI evidence does not exist when `start()` returns.
    /// Without this setting the first
    /// [`ensure_allowed`](Handle::ensure_allowed) call returns `Ok` on a
    /// compromised device, because the detectors that would object have not
    /// run.
    ///
    /// The setting closes that window. It is off by default, because it
    /// costs availability: an early call denies the host's own startup path.
    /// A host that turns it on accepts that cost.
    ///
    /// The window closes once, and it never opens again.
    #[must_use]
    pub fn deny_until_first_full_scan(mut self) -> Self {
        self.deny_until_full_scan = true;
        self
    }

    /// Supplies the callback that serves every category that selects
    /// [`Action::Callback`].
    ///
    /// One callback serves every such category, and the finding names the
    /// category. It never runs for a category with another action.
    ///
    /// The callback runs on the Fidelity worker, after the runtime latches
    /// the state. Keep it short, because it delays the next scan. A host that
    /// wants to work off the worker sends the finding to its own channel from
    /// inside the callback: Fidelity owns no queue, so the host chooses the
    /// depth and the overflow policy.
    #[must_use]
    pub fn on_finding<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&Finding) + Send + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Claims the process-wide slot and starts the runtime.
    ///
    /// The runtime then runs until the process stops. There is no public way
    /// to stop it, and a dropped handle changes nothing.
    ///
    /// # Errors
    ///
    /// Returns a typed [`StartError`] for every fundamental start failure. A
    /// failed start releases the slot, so a corrected retry can succeed.
    pub fn start(self) -> Result<Handle, StartError> {
        // Step 1 claims the slot before anything else, so two concurrent
        // starts cannot both proceed.
        if !claim_slot() {
            return Err(StartError::AlreadyRunning);
        }

        match self.start_claimed() {
            Ok(handle) => Ok(handle),
            Err(error) => {
                // A failed start leaves no process-wide trace, so a corrected
                // retry starts from the same place the first call did. The
                // initial scan runs before the worker exists, so it can latch
                // a category that no handle ever explains.
                set_deny_until_full_scan(false);
                crate::clear_latched();
                release_slot();
                Err(error)
            }
        }
    }

    fn start_claimed(self) -> Result<Handle, StartError> {
        // Step 2 validates the configuration.
        if self.policy.needs_callback() && self.callback.is_none() {
            return Err(StartError::MissingCallback);
        }

        let Some(platform) = Platform::target() else {
            return Err(StartError::UnsupportedTarget);
        };

        if self
            .identity
            .as_ref()
            .is_some_and(|identity| !identity.states_choice_for(platform))
        {
            return Err(StartError::MissingExpectedIdentity { platform });
        }

        // The startup window opens before the backend runs anything, so a
        // host that opted in is never allowed on absent coverage.
        set_deny_until_full_scan(self.deny_until_full_scan);

        // Step 3 constructs the platform backend.
        let environment = crate::backend::build()?;

        // Step 4 completes the initial scan. It runs the cheap detectors,
        // records their outcomes, and latches every qualifying denial. It
        // applies no callback and it stops no process, so `start()` returns
        // first and the worker acts afterwards.
        // A guarded constant needs the signer material, and a fresh read is
        // far too slow for a read path, so the value is captured once here.
        // A build that binds to an identity fails here when the material is
        // absent, because every later read would give a wrong value quietly.
        let identity = resolve_material(BINDS_IDENTITY, signer_material(&*environment), platform)?;

        // The baseline is the state of the process before the host runs any of
        // its own work, so it is captured here and never again. A later scan
        // compares against it. A platform that answers nothing leaves it
        // absent, and the detector reports that rather than a false clean.
        let baseline = match environment.code_regions() {
            Observation::Fact(regions) => Some(regions),
            Observation::Unsupported { .. } | Observation::Failed { .. } => None,
        };

        let detectors = Detectors::new(self.identity, baseline);
        let state = Arc::new(Mutex::new(State::new(fidelity_detect::INVENTORY)));
        let outcomes = detectors.scan_cheap(&*environment, now_unix_ms());
        let initial = fidelity_engine::record(&state, &self.policy, HOOKS, outcomes);

        // Step 5 starts the worker, which runs until the process stops.
        let worker = Worker::new(
            Arc::clone(&state),
            self.policy,
            detectors,
            environment,
            self.callback,
            HOOKS,
        );
        // The handle is built before the thread exists. The initial scan can
        // qualify a callback or a `Crash`, and the lifecycle in
        // `docs/plan/03-runtime-and-api.md` puts both after `start()` builds
        // the handle. A worker that starts first races that construction, so a
        // `Crash` could stop the process before any handle existed.
        let handle = Handle::new(Arc::new(Runtime::new(state, identity)));

        std::thread::Builder::new()
            .name(String::from("fidelity"))
            .spawn(move || worker.run(initial))
            .map_err(|error| StartError::WorkerUnavailable {
                reason: error.kind(),
            })?;

        Ok(handle)
    }
}

/// Whether this build binds guarded constants to a code identity.
///
/// `build.rs` reads `FIDELITY_CODE_IDENTITY` and states the answer here, so
/// the runtime and the macro expansion agree about one build. It is a
/// constant, so an attacker cannot set a run-time flag and skip the check.
const BINDS_IDENTITY: bool = matches!(env!("FIDELITY_BINDS_IDENTITY").as_bytes(), b"true");

// Each reason is a complete sentence, because the start error puts it between
// two of its own.

/// Why an image that carries no signer reports no material.
const NO_SIGNER: &str = "The running image carries no signer, so it is unsigned or signed ad hoc.";

/// Why a platform without the identity capability reports no material.
const NO_PLATFORM_IDENTITY: &str = "The probe reports no code identity on this platform.";

/// Why a failed read reports no material.
const IDENTITY_UNREADABLE: &str = "The code identity read failed.";

/// The signer material that guarded constants derive their key from.
///
/// The error names why the material is absent, because the three reasons take
/// three different answers from the host. Empty material counts as absent: it
/// derives the key that an unbound build derives, so it would read as success
/// and give a wrong value.
fn signer_material(environment: &dyn Environment) -> Result<Box<[u8]>, &'static str> {
    match environment.code_identity() {
        Observation::Fact(identity) => match identity.signer() {
            Some(signer) if !signer.material().is_empty() => Ok(Box::from(signer.material())),
            _ => Err(NO_SIGNER),
        },
        Observation::Unsupported { .. } => Err(NO_PLATFORM_IDENTITY),
        Observation::Failed { .. } => Err(IDENTITY_UNREADABLE),
    }
}

/// Decides what the start does with the material that it read.
///
/// A build that binds to no identity uses an empty value, which is the value
/// that the build side used, so the two agree without a branch on the running
/// state.
///
/// A build that binds to an identity needs the material. Without it every
/// guarded constant decrypts to a wrong value, and a guarded read reports no
/// error, so the start fails here instead. That is the one place where the
/// fault is still visible.
fn resolve_material(
    binds: bool,
    material: Result<Box<[u8]>, &'static str>,
    platform: Platform,
) -> Result<Box<[u8]>, StartError> {
    match material {
        Ok(material) => Ok(material),
        Err(_) if !binds => Ok(Box::from([])),
        Err(reason) => Err(StartError::IdentityBindingUnavailable { platform, reason }),
    }
}

/// The process-wide state that the engine writes through.
const HOOKS: Hooks = Hooks {
    latch: crate::latch,
    full_scan_complete: crate::mark_full_scan_complete,
};

#[cfg(test)]
mod tests {
    use fidelity_core::{
        Baseline, CodeIdentity, Device, Emulation, Environment, Identity, Injection, Lifecycle,
        Observation, PlatformTrust, Signer, Tracer,
    };
    use fidelity_types::{Action, Choice, ExpectedIdentity, Platform, SignalStrength};

    use super::{
        BINDS_IDENTITY, IDENTITY_UNREADABLE, NO_PLATFORM_IDENTITY, NO_SIGNER, resolve_material,
        signer_material,
    };
    use crate::{StartError, exclusive_test};

    /// A probe that answers nothing, so every capability default reports.
    #[derive(Debug)]
    struct Bare;

    impl Identity for Bare {}
    impl Tracer for Bare {}
    impl Injection for Bare {}
    impl Baseline for Bare {}
    impl Device for Bare {}
    impl Emulation for Bare {}

    impl Lifecycle for Bare {}

    impl Environment for Bare {
        fn platform(&self) -> Platform {
            Platform::MacOs
        }
    }

    /// A probe that reports the signer it holds.
    #[derive(Debug)]
    struct Signed(Option<Signer>);

    impl Identity for Signed {
        fn code_identity(&self) -> Observation<CodeIdentity> {
            Observation::Fact(CodeIdentity::new(PlatformTrust::Accepted, self.0.clone()))
        }
    }

    impl Tracer for Signed {}
    impl Injection for Signed {}
    impl Baseline for Signed {}
    impl Device for Signed {}
    impl Emulation for Signed {}

    impl Lifecycle for Signed {}

    impl Environment for Signed {
        fn platform(&self) -> Platform {
            Platform::MacOs
        }
    }

    // The guarded-constant key. `resolve_material` holds the whole decision and
    // it takes the build flag as an argument, so one test binary covers a bound
    // build and an unbound one.

    #[test]
    fn a_build_that_binds_to_no_identity_starts_without_material() {
        let resolved = resolve_material(false, Err(NO_PLATFORM_IDENTITY), Platform::Linux);
        assert!(resolved.is_ok_and(|material| material.is_empty()));
    }

    #[test]
    fn a_build_that_binds_to_an_identity_fails_without_material() {
        let failure = resolve_material(true, Err(NO_SIGNER), Platform::MacOs);
        assert_eq!(
            failure.err(),
            Some(StartError::IdentityBindingUnavailable {
                platform: Platform::MacOs,
                reason: NO_SIGNER,
            })
        );
    }

    #[test]
    fn a_build_that_binds_to_an_identity_starts_with_material() {
        let resolved = resolve_material(true, Ok(Box::from(*b"ABCDE12345")), Platform::MacOs);
        assert_eq!(resolved.ok().as_deref(), Some(b"ABCDE12345".as_slice()));
    }

    #[test]
    fn a_platform_that_answers_nothing_names_that_reason() {
        assert_eq!(signer_material(&Bare).err(), Some(NO_PLATFORM_IDENTITY));
    }

    #[test]
    fn an_image_with_no_signer_names_that_reason() {
        assert_eq!(signer_material(&Signed(None)).err(), Some(NO_SIGNER));
    }

    #[test]
    fn an_empty_signer_counts_as_an_absent_one() {
        // Empty material derives the key that an unbound build derives, so a
        // start that accepted it would give a wrong value at every read.
        let environment = Signed(Some(Signer::new(Vec::new(), "an empty signer")));
        assert_eq!(signer_material(&environment).err(), Some(NO_SIGNER));
    }

    #[test]
    fn a_signer_reports_the_bytes_that_derive_the_key() {
        let environment = Signed(Some(Signer::new(*b"ABCDE12345", "team ABCDE12345")));
        assert_eq!(
            signer_material(&environment).ok().as_deref(),
            Some(b"ABCDE12345".as_slice())
        );
    }

    #[test]
    fn the_failure_tells_the_host_how_to_answer_it() {
        let text = StartError::IdentityBindingUnavailable {
            platform: Platform::Ios,
            reason: IDENTITY_UNREADABLE,
        }
        .to_string();
        assert!(text.contains("FIDELITY_CODE_IDENTITY=none"), "{text}");
    }

    #[test]
    #[expect(
        clippy::assertions_on_constants,
        reason = "the constant is the build input under test, and one named failure reads \
                  better than ten unexplained start failures"
    )]
    fn this_test_run_binds_to_no_identity() {
        assert!(
            !BINDS_IDENTITY,
            "this run set FIDELITY_CODE_IDENTITY, and Cargo signs a test binary ad hoc, so the \
             binary carries no signer and every start test here fails"
        );
    }

    // Every start touches the process-wide slot, so each test here holds the
    // exclusive guard.

    #[test]
    fn a_callback_category_without_a_callback_fails_the_start() {
        let _guard = exclusive_test();
        let failure = crate::new()
            .ui_abuse(Action::Callback, SignalStrength::High)
            .start()
            .err();
        assert_eq!(failure, Some(StartError::MissingCallback));
    }

    #[test]
    fn a_callback_category_with_a_callback_passes_validation() {
        let _guard = exclusive_test();
        let failure = crate::new()
            .ui_abuse(Action::Callback, SignalStrength::High)
            .on_finding(|_| {})
            .start()
            .err();
        assert_ne!(failure, Some(StartError::MissingCallback));
    }

    #[test]
    fn identity_without_a_choice_for_the_target_fails_the_start() {
        let _guard = exclusive_test();
        // The value states a choice for one platform only, so at most one
        // target can satisfy it.
        let other = if Platform::target() == Some(Platform::Windows) {
            ExpectedIdentity::new().linux(Choice::AcceptUnsupported)
        } else {
            ExpectedIdentity::new().windows(Choice::AcceptUnsupported)
        };
        let failure = crate::new().expected_identity(other).start().err();
        assert!(matches!(
            failure,
            Some(StartError::MissingExpectedIdentity { .. })
        ));
    }

    #[test]
    fn a_default_builder_states_a_complete_configuration() {
        // Neither validation rule objects to an empty builder, so a start
        // reaches the platform backend without any host input.
        let builder = crate::new();
        let shown = format!("{builder:?}");
        assert!(shown.contains("identity: None"), "{shown}");
        assert!(shown.contains("callback: false"), "{shown}");
    }

    /// A configuration that always fails validation, before the start
    /// reaches a platform backend. Every test that needs a failed start uses
    /// this, so the tests behave the same on a target with a backend and on a
    /// target without one.
    fn invalid() -> crate::Builder {
        crate::new().ui_abuse(Action::Callback, SignalStrength::High)
    }

    #[test]
    fn a_failed_start_releases_the_slot() {
        let _guard = exclusive_test();
        let first = invalid().start().err();
        let second = invalid().start().err();
        assert_eq!(first, second, "the slot did not return to the next caller");
    }

    #[test]
    fn a_released_slot_never_reports_a_singleton_conflict() {
        let _guard = exclusive_test();
        invalid().start().ok();
        let failure = invalid().start().err();
        assert_ne!(failure, Some(StartError::AlreadyRunning));
    }

    #[test]
    fn a_failed_start_closes_the_startup_window() {
        let _guard = exclusive_test();
        invalid().deny_until_first_full_scan().start().ok();
        assert!(
            !crate::denies_until_full_scan(),
            "a failed start must leave no process-wide trace"
        );
    }

    #[test]
    fn a_setting_reaches_only_its_own_category() {
        let builder = crate::new()
            .integrity(Action::Crash, SignalStrength::Low)
            .debugging(Action::Deny, SignalStrength::High);
        let shown = format!("{builder:?}");
        assert!(shown.contains("Crash") && shown.contains("Deny"), "{shown}");
    }
}
