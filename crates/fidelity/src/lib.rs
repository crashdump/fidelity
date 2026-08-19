//! Detect hostile changes to an application's runtime environment, and apply
//! a response that the host selects.
//!
//! This crate is the supported entry point, and it alone follows `SemVer`.
//! Every other crate in the workspace is an internal implementation detail.
//!
//! # Status
//!
//! Five platforms run. macOS, iOS, Windows, Linux, and Android answer image
//! identity, compare executable memory against a baseline that `start()`
//! captured, and read tracer state. Windows, Linux, and Android add
//! unaccounted code, and Android adds device compromise. A target that ships
//! no probe crate returns [`StartError::PlatformUnavailable`],
//! because a backend that reports a clean environment while it examines
//! nothing is worse than a visible failure. A platform counts as supported
//! only after its full release tests exists, and none does yet.
//!
//! One limit is worth knowing before you ship. An x64 image that runs under
//! the emulation of an ARM64 Windows reports unaccounted code on every clean
//! run, because the translator writes code that no file backs. Measured on
//! 2026-08-18. The test record states the figure, and an ARM64 image on
//! the same machine reports clean.
//!
//! # Shape
//!
//! One runtime runs per process, so this example compiles without a run.
//!
//! ```no_run
//! use fidelity::{Action, SignalStrength};
//!
//! let started = fidelity::new()
//!     .integrity(Action::Crash, SignalStrength::High)
//!     .debugging(Action::Deny, SignalStrength::Medium)
//!     .start();
//!
//! match started {
//!     Ok(handle) => {
//!         // Call immediately before a protected operation.
//!         handle.ensure_allowed()?;
//!     }
//!     // Treat a start failure as fatal, or run knowingly unprotected.
//!     Err(error) => eprintln!("fidelity did not start: {error}"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Features
//!
//! Both are off by default, so a default build resolves to no external crate.
//!
//! - `serde` implements `Serialize` for the public types, so a host that
//!   exports a finding chooses its own format.
//! - `tracing` reports internal events. Each one names the detector, the
//!   category, the strength, and the action. Fidelity installs no subscriber,
//!   so the host installs its own and the events go where its own logs go.
//!
//! # What the runtime promises
//!
//! One runtime runs per process. It starts once and runs until the process
//! stops, because a security library must not offer an off-switch. The
//! configuration is immutable after the start.
//!
//! A denial latch is permanent and cooperative. It denies nothing on its own,
//! so the host must call [`Handle::ensure_allowed`] immediately before each
//! protected operation.
//!
//! Fidelity raises the cost of an attack. It cannot make a user-mode process
//! tamper-proof, and an attacker who runs inside the process can forge
//! findings, suppress checks, and bypass responses.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

mod backend;
pub(crate) mod builder;
mod error;
mod handle;
mod secret;

pub use builder::Builder;
pub use error::{DenialReason, Denied, StartError};
pub use handle::Handle;
pub use secret::Secret;

#[doc(hidden)]
pub use secret::__guarded;

/// Guards a host literal against this build and the running code identity.
///
/// The macro encrypts the literal at build time and expands the decryption at
/// the call site, so the plaintext never reaches the binary and no shared
/// reader exists. It returns a [`Secret`], which derefs to `str` and wipes its
/// buffer on drop.
///
/// ```ignore
/// let host = fidelity::guarded!(&handle, "api.example.com");
/// let url = format!("https://{}/v1", &*host);
/// ```
///
/// A repackaged application derives another key and reads another value. There
/// is no error and no branch, so there is nothing to invert.
///
/// The build reads `FIDELITY_BUILD_SEED` and `FIDELITY_CODE_IDENTITY`, and it
/// fails when either is absent. The identity value names the kind of material
/// before it states the material, as in `apple:ABCDE12345`, so a value that
/// belongs to another target fails the build. See the delivery notes for what
/// to set them to.
pub use fidelity_macros::guarded;

pub use fidelity_types::{
    Action, AuthenticodeThumbprint, BoundedText, Category, CategorySet, CertificateSha256, Choice,
    CodeRequirement, ContentDigest, Detector, DetectorState, Evidence, ExpectedIdentity, Finding,
    IdentityError, MAX_EVIDENCE_BYTES, Outcome, Platform, SignalStrength, Snapshot, TeamIdentifier,
    UiObservation,
};

/// Creates a builder for the process-wide runtime.
///
/// See [`Builder`] for the configuration surface.
#[must_use]
pub fn new() -> Builder {
    Builder::default()
}

/// The process-wide runtime slot. One runtime holds it for the life of the
/// process, and only a failed start returns it.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// The permanent denial latch.
///
/// It lives here, in the facade, rather than in the engine, so that an
/// isolated test runtime keeps its own denial state. It is one atomic word,
/// so a check reads it without a lock and without an allocation.
///
/// The engine holds the same latch inside its state, because that is what
/// [`Handle::snapshot`] reports. Every writer updates the engine and this word
/// while it holds the state lock, so the two never disagree: a host that sees
/// a denial here always reads a snapshot that explains it, and a snapshot that
/// shows a latch always denies.
static LATCHED: AtomicU32 = AtomicU32::new(0);

/// Whether the worker completed its first full scan.
///
/// The initial scan covers the cheap detectors only, so this stays false
/// until every detector has run once.
static FULL_SCAN_DONE: AtomicBool = AtomicBool::new(false);

/// Whether the host asked to deny until the first full scan completes.
///
/// The configuration is immutable after the start, and one runtime runs per
/// process, so a static holds it without a lock.
static DENY_UNTIL_FULL_SCAN: AtomicBool = AtomicBool::new(false);

pub(crate) fn claim_slot() -> bool {
    RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub(crate) fn release_slot() {
    RUNNING.store(false, Ordering::Release);
}

pub(crate) fn latched_categories() -> CategorySet {
    CategorySet::from_bits(LATCHED.load(Ordering::Acquire))
}

pub(crate) fn latch(category: Category) {
    let mut set = CategorySet::new();
    set.insert(category);
    LATCHED.fetch_or(set.bits(), Ordering::AcqRel);
}

/// Clears the latch that a start claimed and then abandoned.
///
/// A latch never clears while a runtime lives. This is the one exception, and
/// it is safe for one reason: the caller holds the process-wide slot, so no
/// runtime exists to own the state. The initial scan of a start that then
/// fails can latch a category, and the handle that would explain it is never
/// built. Without this, a later start returns a handle that denies for a
/// category its own snapshot does not hold.
pub(crate) fn clear_latched() {
    LATCHED.store(0, Ordering::Release);
}

pub(crate) fn full_scan_complete() -> bool {
    FULL_SCAN_DONE.load(Ordering::Acquire)
}

pub(crate) fn mark_full_scan_complete() {
    FULL_SCAN_DONE.store(true, Ordering::Release);
}

pub(crate) fn denies_until_full_scan() -> bool {
    DENY_UNTIL_FULL_SCAN.load(Ordering::Acquire)
}

pub(crate) fn set_deny_until_full_scan(deny: bool) {
    DENY_UNTIL_FULL_SCAN.store(deny, Ordering::Release);
}

/// Serializes the tests that touch the process-wide statics, and clears
/// those statics.
///
/// `RUNNING` and `LATCHED` outlive one test, and Cargo runs the tests of one
/// binary on parallel threads. Without this guard a latch from one test
/// denies an unrelated test, and two starts race for the slot.
#[cfg(test)]
pub(crate) fn exclusive_test() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, PoisonError};

    static SERIAL: Mutex<()> = Mutex::new(());

    let guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    RUNNING.store(false, Ordering::Release);
    LATCHED.store(0, Ordering::Release);
    FULL_SCAN_DONE.store(false, Ordering::Release);
    DENY_UNTIL_FULL_SCAN.store(false, Ordering::Release);
    guard
}

#[cfg(test)]
mod tests {
    use super::{Category, exclusive_test, latch, latched_categories};

    #[test]
    fn a_latch_shows_up_in_the_process_wide_state() {
        let _guard = exclusive_test();
        latch(Category::Virtualization);
        assert!(latched_categories().contains(Category::Virtualization));
    }

    #[test]
    fn a_latch_never_clears() {
        let _guard = exclusive_test();
        latch(Category::Virtualization);
        latch(Category::Instrumentation);
        assert!(latched_categories().contains(Category::Virtualization));
    }

    #[test]
    fn a_clean_process_latches_nothing() {
        let _guard = exclusive_test();
        assert!(latched_categories().is_empty());
    }
}
