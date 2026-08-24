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
//! Every capability except `device` answers. `dispatch` reads the import table
//! of the main module, which Windows binds fully at load, so a later change to
//! one entry is a redirect.
//!
//! No release calls this platform supported. That label needs a real clean and
//! a real hostile control for every capability above, and
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
mod dispatch;
mod emulation;
mod identity;
mod image_catalog;
mod injection;
mod local_agent;
mod sys;
mod tracer;

use fidelity_core::{Device, Environment, Lifecycle, VerifiedBoot};
use fidelity_types::Platform;

/// The Windows view of the running process.
#[derive(Debug)]
pub struct WindowsEnvironment;

impl WindowsEnvironment {
    /// Creates the Windows environment.
    #[must_use]
    pub fn new() -> Self {
        // The first Windows socket call loads fixed network code. Load it
        // before `start()` captures its executable-memory baseline.
        let _ = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0));
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

impl VerifiedBoot for WindowsEnvironment {}

// Windows asks nothing of the worker thread, so the default answers.
impl Lifecycle for WindowsEnvironment {}
