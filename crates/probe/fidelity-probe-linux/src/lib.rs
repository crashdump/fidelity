//! Operating-system access for Linux.
//!
//! This crate reports facts. It selects no response, it calculates no score,
//! and it never reports a failed call as a clean result. All `unsafe` code
//! lives under the `sys` boundary module.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.
//!
//! # Status
//!
//! The `tracer` capability answers. `identity` waits for fs-verity, so it
//! reports `Unsupported` through the trait default.
//!
//! # Layout
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that this platform does not answer gets an empty `impl`, which
//! states the gap without a method body to read.
//!
//! `sys/` reads the operating system, and it interprets nothing. The reader
//! that turns procfs text into values lives in `fidelity-formats`, because a
//! pure reader is not platform code: this crate compiles on Linux only, so a
//! reader inside it could only be tested on Linux. See
//! [delivery](../../../../docs/plan/06-delivery.md).

#![cfg(target_os = "linux")]

mod baseline;
mod injection;
mod sys;
mod tracer;

use fidelity_core::{Device, Environment, Identity, Lifecycle};
use fidelity_types::Platform;

/// The Linux view of the running process.
#[derive(Debug)]
pub struct LinuxEnvironment;

impl LinuxEnvironment {
    /// Creates the Linux environment.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for LinuxEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for LinuxEnvironment {
    fn platform(&self) -> Platform {
        Platform::Linux
    }
}

// `Tracer` carries real platform code, so it lives in `tracer.rs`. `Identity`
// waits for fs-verity. The empty `impl` states that gap, and the trait default
// reports `Unsupported` until platform code replaces it.
impl Identity for LinuxEnvironment {}

// Linux cannot answer `device`. The category reports the loss of a privilege
// boundary that the operating system holds against its own user, and a Linux
// host grants that user root by design. A root shell, a permissive policy, and
// a custom kernel are all ordinary there, so the question does not apply.
impl Device for LinuxEnvironment {}

// Linux asks nothing of the worker thread, so the default answers.
impl Lifecycle for LinuxEnvironment {}
