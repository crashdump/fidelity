//! Readers for the firmware identity that Linux and Windows both report.
//!
//! The DMTF System Management BIOS specification states what the firmware says
//! about the machine, and both platforms carry it. Linux parses the table in
//! the kernel and writes each field as text under `/sys/class/dmi/id/`, so a
//! probe there reads two files. Windows hands the whole table to the process,
//! through `GetSystemFirmwareTable`, so a probe there parses it with
//! [`system`].
//!
//! [`vendor`] holds the judgment, and it sits here rather than in a probe
//! crate. The two platforms read the same two DMTF fields, so one copy of the
//! rule cannot disagree with itself.
//!
//! The readers take bytes and text, and they open no file.

pub mod system;
pub mod vendor;
