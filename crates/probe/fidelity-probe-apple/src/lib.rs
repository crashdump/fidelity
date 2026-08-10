//! Operating-system access for macOS and iOS.
//!
//! This crate reports facts. It selects no response, it calculates no score,
//! and it never reports a failed call as a clean result. All `unsafe` code
//! lives under the `sys` boundary module.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.
//!
//! # Layout
//!
//! `sys/` holds the operating-system boundary, and macOS and iOS share it.
//! `common/` holds the capability bodies that both systems run. `macos/` and
//! `ios/` hold one module per capability, named as
//! `fidelity_core::capability` names it.
//!
//! The two systems share one crate because they share every framework binding
//! under `sys/`. A crate for each would duplicate all of them.
//!
//! # iOS
//!
//! iOS reports `tracer` and `baseline`. Both read the interface that macOS
//! reads, so `common/` holds each body once and each system binds it to its
//! own environment. iOS reports no platform trust, because the kernel enforces
//! code signing and exposes no equivalent of `SecCodeCheckValidity`.
//!
//! # macOS
//!
//! Platform trust asks the operating system whether the running image
//! satisfies `anchor apple generic`. Measured on macOS 26 and ARM64, that is
//! the only check that separates a distributed image from a repackaged one. A
//! validity check with no requirement cannot fail in a running process,
//! because the kernel stops a modified image before it executes.
//!
//! The signer material is the team identifier. It survives a version change
//! and a certificate change inside one team, and a repackaged image loses it.

#![cfg(any(target_os = "macos", target_os = "ios"))]

mod common;
mod sys;

#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "ios")]
pub use ios::IosEnvironment;
#[cfg(target_os = "macos")]
pub use macos::MacEnvironment;
