//! One trait for each capability that a platform can offer.
//!
//! # The pattern
//!
//! A capability is one question that detectors ask the operating system. Each
//! one gets its own trait here, and its own module in every probe crate under
//! the same file name. To find out which systems answer a question, list that
//! file name across the probe crates.
//!
//! Every method carries a default that reports
//! [`Unsupported`](crate::Observation::Unsupported), so:
//!
//! - a probe implements the capabilities that its platform offers, and writes
//!   an empty `impl` for the rest. The empty `impl` states the gap, and a
//!   reader sees it without reading any method body; and
//! - a new capability breaks no probe crate, because every probe inherits the
//!   default until somebody writes the platform code.
//!
//! [`Environment`](crate::Environment) inherits every capability trait, so the
//! engine holds one value. A detector takes the narrow trait it reads, not the
//! whole environment, so its signature states what it touches.
//!
//! # Adding a capability
//!
//! 1. Add the fact types to [`fact`](crate::fact), in a module of the same
//!    name.
//! 2. Add the trait here, with a default that reports `Unsupported`.
//! 3. Add it as a supertrait of `Environment`.
//! 4. Implement it in each probe crate that can answer, in a module of the
//!    same name. Write an empty `impl` in the rest.
//! 5. Add the detector to `fidelity-detect`, in the module of its category.
//!
//! # The set
//!
//! `docs/plan/04-detectors-and-platforms.md` holds the categories, and
//! `docs/research/platform-notes.md` holds the mechanism candidates. A
//! capability arrives with its platform evidence, and not before, so this
//! list states which questions exist rather than which systems answer them.
//! The coverage matrix in `docs/plan/06-delivery.md` holds that second table,
//! and a test keeps it true.
//!
//! | Capability | Category | Answers |
//! |---|---|---|
//! | [`identity`] | `Integrity` | Is this the expected image, and who signed it? |
//! | [`baseline`] | `Integrity` | Did the mappings or the dispatch targets change? |
//! | [`tracer`] | `Debugging` | Does a debugger or a tracer hold this process? |
//! | [`injection`] | `Instrumentation` | Is a hook, an injection, or an agent present? |
//! | [`device`] | `DeviceCompromise` | Is the operating-system security model weakened? |
//! | `emulation` | `Virtualization` | Does this run in an emulator or a virtual machine? |
//! | `interface` | `UiAbuse` | Does another application read or drive the interface? |
//!
//! One capability answers no question and reports no finding:
//!
//! | Capability | Purpose |
//! |---|---|
//! | [`lifecycle`] | What the worker thread must do on this platform |
//!
//! `lifecycle` exists so that the worker stays portable. Android attaches the
//! worker thread to the JVM as a daemon, Apple gives the thread a quality of
//! service, and a mobile system reports that it resumed the application, which
//! makes a full scan the worker's next work item. Each one is platform code,
//! so each one belongs to a probe. Without this capability the engine would
//! gate on the target, and platform code would leave the probe crates.

pub mod baseline;
pub mod device;
pub mod identity;
pub mod injection;
pub mod lifecycle;
pub mod tracer;

pub use baseline::Baseline;
pub use device::Device;
pub use identity::Identity;
pub use injection::Injection;
pub use lifecycle::Lifecycle;
pub use tracer::Tracer;
