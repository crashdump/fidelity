//! Readers for the Mach-O structures that an Apple system reports.
//!
//! An Apple image carries its code signature inside itself, as the data that
//! the `LC_CODE_SIGNATURE` load command names. The probe maps those bytes
//! through its own `sys` boundary, and the readers here interpret them.
//!
//! iOS needs this because it has no other route. The iOS SDK ships neither
//! `SecCode.h` nor `SecTask.h`, so `SecCodeCopySigningInformation`, which
//! macOS uses to read the team identifier, does not exist there. The signature
//! that the image already carries is the remaining documented source.
//!
//! Every value here is big-endian, whatever the machine runs, because the
//! blob format states that.

pub mod entitlements;
pub mod signature;
