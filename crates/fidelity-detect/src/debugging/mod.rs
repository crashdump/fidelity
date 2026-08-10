//! Detectors for the `Debugging` category.
//!
//! The category asks whether a debugger or a tracer is interacting, or has
//! interacted, with the process. The engine keeps the strongest observation,
//! so a tracer that attaches once and detaches stays in the report.
//!
//! The [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes
//! timing tricks and exception abuse from this category, because both
//! destabilize the host that Fidelity runs inside. What is left is the state
//! that the kernel already holds.

mod tracer;

pub use tracer::TRACER_PRESENT;

pub(crate) use tracer::tracer_present;
