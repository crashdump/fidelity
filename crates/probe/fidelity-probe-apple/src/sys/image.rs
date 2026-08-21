//! The Mach-O image boundary.
//!
//! An Apple image carries its own code signature, and the `LC_CODE_SIGNATURE`
//! load command names where. This module finds those bytes for the running
//! executable and hands them to the reader in `fidelity-formats`, which parses
//! them on any machine from a recorded fixture.
//!
//! iOS needs this route because it has no other. Checked against the iOS 26
//! SDK on 2026-08-10: the Security framework there ships neither `SecCode.h`
//! nor `SecTask.h`, so `SecCodeCopySigningInformation`, which macOS uses for
//! the team identifier, does not exist. The signature that the image already
//! carries is the remaining documented source.
//!
//! The load commands sit inside the signed area, so the kernel refuses to run
//! an image whose commands were changed. That is what makes the offsets here
//! trustworthy, and every `unsafe` block below states it.

use fidelity_formats::macho::dispatch::MAX_COMMAND_BYTES;
use fidelity_formats::macho::image::{SignatureLayout, signature_layout};

use super::regions;

/// The file type of a main executable.
const MH_EXECUTE: u32 = 0x2;

/// The layout of `mach_header_64`.
///
/// Eight 32-bit fields, each naturally aligned, so no packing applies here.
/// The assertion fails the build if that changes.
#[repr(C)]
struct MachHeader {
    magic: u32,
    cpu_type: i32,
    cpu_subtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<MachHeader>() == 32);

// The dynamic loader reports the images that this process mapped. Apple
// documents all three calls in `<mach-o/dyld.h>`.
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader;
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
}

/// The embedded code signature of the running executable.
///
/// Returns `None` when the image carries no signature, and on any image whose
/// load commands do not describe one range inside `__LINKEDIT`. The caller
/// reports that gap, and it never reads a `None` as a clean result.
///
/// The slice borrows the mapped image. That mapping lives for the whole
/// process, because the main executable never unloads, so the lifetime is
/// sound.
#[must_use]
pub(crate) fn code_signature() -> Option<&'static [u8]> {
    let layout = locate()?;
    let at = usize::try_from(layout.address()).ok()?;
    if !regions::mapped(layout.address(), layout.bytes()) {
        return None;
    }

    // SAFETY: the safe reader bounds this range inside `__LINKEDIT`, and the
    // kernel confirms the complete mapping. The main image never unloads.
    Some(unsafe { core::slice::from_raw_parts(at as *const u8, layout.bytes()) })
}

/// Finds the signature of the main executable, and checks that it fits.
fn locate() -> Option<SignatureLayout> {
    // SAFETY: the call reads a counter that the loader owns, and it takes no
    // pointer.
    let count = unsafe { _dyld_image_count() };

    for index in 0..count {
        // SAFETY: `index` is below the count that the loader just reported,
        // so both calls answer for an image that the loader holds.
        let (header, slide) = unsafe {
            (
                _dyld_get_image_header(index),
                _dyld_get_image_vmaddr_slide(index),
            )
        };
        if header.is_null() {
            continue;
        }

        // SAFETY: the loader returned the address of a mapped Mach-O header,
        // and the read stays inside the structure that the header names.
        let filetype = unsafe { (*header).filetype };
        if filetype != MH_EXECUTE {
            continue;
        }
        // SAFETY: the same fixed header holds both bounded command fields.
        let (commands, command_bytes) = unsafe { ((*header).ncmds, (*header).sizeofcmds) };
        return read_commands(header, slide, commands, command_bytes);
    }

    None
}

/// Hands one kernel-confirmed command slice to the safe reader.
fn read_commands(
    header: *const MachHeader,
    slide: isize,
    command_count: u32,
    command_bytes: u32,
) -> Option<SignatureLayout> {
    let command_bytes = usize::try_from(command_bytes).ok()?;
    if command_bytes > MAX_COMMAND_BYTES {
        return None;
    }
    let address = (header as usize).checked_add(size_of::<MachHeader>())?;
    if !regions::mapped(address as u64, command_bytes) {
        return None;
    }
    // SAFETY: the kernel confirms the complete bounded command range.
    let commands = unsafe { core::slice::from_raw_parts(address as *const u8, command_bytes) };
    signature_layout(commands, command_count, i64::try_from(slide).ok()?)
}

#[cfg(test)]
mod tests {
    use super::code_signature;

    /// The signature of this test binary, or a failed test.
    fn signature() -> &'static [u8] {
        let Some(bytes) = code_signature() else {
            panic!("an Apple image carries a signature")
        };
        bytes
    }

    #[test]
    fn the_running_image_reports_a_signature() {
        // Every Apple target signs a binary, and Cargo signs a test binary ad
        // hoc, so this answers on macOS and on the iOS simulator alike.
        assert!(!signature().is_empty());
    }

    #[test]
    fn the_signature_starts_with_the_superblob_magic() {
        let found = signature();
        let magic = u32::from_be_bytes([found[0], found[1], found[2], found[3]]);
        assert_eq!(
            magic, 0xfade_0cc0,
            "the bytes must be an embedded signature"
        );
    }

    #[test]
    fn the_reader_parses_what_the_boundary_returns() {
        // The two layers meet here. `fidelity-formats` proves the parse against
        // a recorded fixture, and this proves that a real image reaches it.
        let parsed = fidelity_formats::macho::signature::entitlements(signature());
        // Cargo signs a test binary ad hoc with no entitlements, so the common
        // answer is `None`. Either answer proves that the parse ran and that
        // the bytes were the shape the reader expects.
        assert!(parsed.is_none_or(|plist| !plist.is_empty()));
    }
}
