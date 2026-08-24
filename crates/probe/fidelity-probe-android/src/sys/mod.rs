//! The Android operating-system boundary.
//!
//! Every `unsafe` block in this crate lives under this module, and each one
//! states the invariant that it depends on. The module exposes safe functions
//! only, so no caller outside it holds a raw pointer.
//!
//! The module interprets nothing. It reads, and `fidelity-formats` turns the
//! result into plain Rust values.
//!
//! One file per operating-system interface.

pub(crate) mod apk;
pub(crate) mod catalog;
pub(crate) mod dispatch;
pub(crate) mod jvm;
pub(crate) mod maps;
pub(crate) mod property;
pub(crate) mod status;
