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
//! No capability is implemented yet, so `WindowsEnvironment` answers `Unsupported`
//! everywhere and the `fidelity` facade does not construct it. `start()`
//! returns `StartError::PlatformUnavailable` on this platform. A probe that
//! answered `Unsupported` to everything while the runtime reported success
//! would claim coverage that nothing produced.
//!
//! # Layout
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that this platform does not answer gets an empty `impl`, which
//! states the gap without a method body to read.
//!
//! `sys/` will hold the Win32 bindings, one file per library: `wintrust.rs` for Authenticode, `psapi.rs` for the loader view, and so on.

#![cfg(target_os = "windows")]

mod sys;

use fidelity_core::{Baseline, Device, Environment, Identity, Injection, Lifecycle, Tracer};
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

// No capability is implemented yet. Each empty `impl` states one gap, and the
// trait default reports `Unsupported` until platform code replaces it.
impl Identity for WindowsEnvironment {}
impl Tracer for WindowsEnvironment {}
impl Injection for WindowsEnvironment {}
impl Baseline for WindowsEnvironment {}

// Windows cannot answer `device`. The category reports the loss of a privilege
// boundary that the operating system holds against its own user, and Windows
// grants that user administrator rights by design. The question does not apply
// rather than waiting for code.
impl Device for WindowsEnvironment {}

// Windows asks nothing of the worker thread, so the default answers.
impl Lifecycle for WindowsEnvironment {}
