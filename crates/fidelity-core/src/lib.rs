//! The boundary between platform probes and detectors.
//!
//! A platform probe crate implements the [`capability`] traits and
//! returns narrow [facts](fact) from operating-system interfaces. A detector
//! consumes one capability and turns its facts into a category, a strength,
//! and typed evidence. Neither side imports the other, so Cargo enforces the
//! separation.
//!
//! # Two axes
//!
//! Capabilities are the trait axis, and operating systems are the crate axis.
//! A capability is one question, and it gets one trait here plus one module of
//! the same name in every probe crate. An operating system gets one crate
//! under `crates/probe/`, which holds all of its `unsafe` code and all of its
//! platform dependencies.
//!
//! [`capability`] holds the pattern and the steps that add a new one.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.

#![forbid(unsafe_code)]

pub mod capability;
pub mod fact;

mod environment;
mod observation;

pub use capability::{
    Baseline, Device, Dispatch, Emulation, Identity, Injection, Lifecycle, Tracer,
};
pub use environment::Environment;
pub use fact::{
    CodeIdentity, CodeOrigin, CodeRegions, DispatchTargets, IdentityMatch, MachineHost,
    PlatformTrust, Region, Signer, SystemBuild, Target, TracerState, WorkerSetup,
};
pub use observation::Observation;

/// The reason a build reports a fact that no probe supplies.
pub(crate) const NO_PROBE: &str = "this build ships no probe for this fact";
