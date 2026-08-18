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
//! The `baseline`, `injection`, `tracer`, and `identity` capabilities answer.
//! `identity` reports platform trust only where the deployment enables
//! fs-verity, and it reports no signer at all, so `guarded!()` still refuses a
//! Linux binding. The `identity` module states why.
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
mod identity;
mod injection;
mod sys;
mod tracer;

use fidelity_core::{Device, Emulation, Environment, Lifecycle};
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

// Linux cannot answer `device`. The category reports the loss of a privilege
// boundary that the operating system holds against its own user, and a Linux
// host grants that user root by design. A root shell, a permissive policy, and
// a custom kernel are all ordinary there, so the question does not apply.
impl Device for LinuxEnvironment {}

// Linux can answer `emulation`, and no code exists yet. The kernel states
// what runs it, in more than one place. The block is the clean control: this
// project owns a Linux guest, which is a hostile control, and it owns no bare
// metal Linux to compare it against. A detector with one control is a
// detector nobody measured.
impl Emulation for LinuxEnvironment {}

// Linux asks nothing of the worker thread, so the default answers.
impl Lifecycle for LinuxEnvironment {}
