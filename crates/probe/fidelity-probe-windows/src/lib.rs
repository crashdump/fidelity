//! Operating-system access for Windows.
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
//!
//! No release calls this platform supported. That label needs real clean and
//! hostile evidence for every capability above, and
//! [verification](../../../../docs/plan/05-verification.md) alone defines it.
//!
//! # Layout
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that this platform does not answer gets an empty `impl`, which
//! states the gap without a method body to read.
//!
//! `sys/` holds the Win32 bindings, one file per interface.

#![cfg(target_os = "windows")]

mod baseline;
mod identity;
mod injection;
mod sys;
mod tracer;

use fidelity_core::{Device, Environment, Lifecycle};
use fidelity_types::Platform;

/// The Windows view of the running process.
#[derive(Debug)]
pub struct WindowsEnvironment;

impl WindowsEnvironment {
    /// Creates the Windows environment.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WindowsEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for WindowsEnvironment {
    fn platform(&self) -> Platform {
        Platform::Windows
    }
}

// Windows cannot answer `device`. The category reports the loss of a privilege
// boundary that the operating system holds against its own user, and Windows
// grants that user administrator rights by design. The question does not apply
// rather than waiting for code.
impl Device for WindowsEnvironment {}

// Windows asks nothing of the worker thread, so the default answers.
impl Lifecycle for WindowsEnvironment {}
