//! The Windows operating-system boundary.
//!
//! Every `unsafe` block in this crate lives under this module, and each one
//! states the invariant that it depends on. The module exposes safe functions
//! only, so no caller outside it holds a raw pointer.
//!
//! One file per operating-system interface. Most of these functions come from
//! Kernel32.dll, which the Rust standard library already links. The two that
//! answer the identity question name their own library with `#[link]`, so the
//! crate still takes no build script.

pub(crate) mod crypt;
pub(crate) mod debug;
pub(crate) mod image;
pub(crate) mod memory;
pub(crate) mod psapi;
pub(crate) mod wintrust;
