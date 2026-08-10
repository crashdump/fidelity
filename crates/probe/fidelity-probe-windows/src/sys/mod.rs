//! The Windows operating-system boundary.
//!
//! Every `unsafe` block in this crate lives under this module, and each one
//! states the invariant that it depends on. The module exposes safe functions
//! only, so no caller outside it holds a raw pointer.
//!
//! One file per operating-system interface.
