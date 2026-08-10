//! Pure readers of the data that an operating system reports.
//!
//! A reader here takes bytes or text and returns plain Rust values. It calls
//! no operating system, it holds no `unsafe` code, and it depends on no other
//! crate. A recorded fixture therefore tests it on any machine, which is the
//! whole reason the layer exists.
//!
//! This crate is not an operating system, so it does not live on the platform
//! axis under `crates/probe/` and it carries no target condition. A probe crate
//! reads the bytes through its own `sys` boundary, then calls a reader here.
//! See [delivery](../../../docs/plan/06-delivery.md).
//!
//! One module per format. `procfs` serves Linux and Android, and `macho`
//! serves macOS and iOS, which is the second reason a shared crate beats a
//! module inside one platform crate.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.

#![forbid(unsafe_code)]

pub mod apk;
pub mod macho;
pub mod procfs;
