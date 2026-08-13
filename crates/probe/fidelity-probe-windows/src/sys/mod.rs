//! The Windows operating-system boundary.
//!
//! Every `unsafe` block in this crate lives under this module, and each one
//! states the invariant that it depends on. The module exposes safe functions
//! only, so no caller outside it holds a raw pointer.
//!
//! One file per operating-system interface. Every function that these modules
//! declare comes from Kernel32.dll, which the Rust standard library already
//! links, so the crate names no second library and takes no build script.

pub(crate) mod debug;
pub(crate) mod memory;
pub(crate) mod psapi;
