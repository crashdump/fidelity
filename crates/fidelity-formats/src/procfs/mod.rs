//! Readers for the process filesystem that Linux and Android share.
//!
//! Android runs a Linux kernel, so both platforms read the same files with the
//! same shape. Each probe crate reads the bytes through its own `sys`
//! boundary, then calls a reader here.
//!
//! One module for each file.

pub mod maps;
pub mod status;
