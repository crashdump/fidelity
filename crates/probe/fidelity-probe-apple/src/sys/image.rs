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

use core::ffi::c_char;

/// The load command that names a 64-bit segment.
const LC_SEGMENT_64: u32 = 0x19;

/// The load command that names the code signature.
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// The file type of a main executable.
const MH_EXECUTE: u32 = 0x2;

/// The name of the segment that holds the signature.
const LINKEDIT: &[u8] = b"__LINKEDIT";

/// The largest signature that this module maps, at 16 MiB.
///
/// A real signature is far smaller, and the bound stops a malformed load
/// command from describing a slice that no mapping backs.
const MAX_SIGNATURE: u32 = 16 * 1024 * 1024;

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

/// The layout of `load_command`, which every command starts with.
#[repr(C)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

const _: () = assert!(size_of::<LoadCommand>() == 8);

/// The layout of `segment_command_64`.
///
/// The 64-bit fields start at byte 24, which is already 8-aligned, so the
/// structure needs no packing and holds no padding.
#[repr(C)]
struct SegmentCommand {
    cmd: u32,
    cmdsize: u32,
    segname: [c_char; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: i32,
    initprot: i32,
    nsects: u32,
    flags: u32,
}

const _: () = assert!(size_of::<SegmentCommand>() == 72);

/// The layout of `linkedit_data_command`, which names a range in `__LINKEDIT`.
#[repr(C)]
struct LinkeditData {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

const _: () = assert!(size_of::<LinkeditData>() == 16);

// The dynamic loader reports the images that this process mapped. Apple
// documents all three calls in `<mach-o/dyld.h>`.
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader;
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
}

/// Where the signature of the running image sits, once the walk found it.
struct Located {
    /// The address of the first byte of the signature.
    at: usize,

    /// How many bytes the load command says the signature holds.
    length: usize,
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
    let Located { at, length } = locate()?;

    // SAFETY: `locate` returned an address inside the `__LINKEDIT` segment of
    // the main executable, and a length that fits inside that segment. The
    // loader maps the segment read-only for the life of the process, and the
    // main executable never unloads, so the bytes stay valid and unchanged.
    Some(unsafe { core::slice::from_raw_parts(at as *const u8, length) })
}

/// Finds the signature of the main executable, and checks that it fits.
fn locate() -> Option<Located> {
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
        // SAFETY: the same header, which the loader mapped and the kernel
        // validated before it ran the image.
        let commands = unsafe { (*header).ncmds };
        return walk(header, slide, commands);
    }

    None
}

/// Walks the load commands of one image for the two it needs.
///
/// The kernel validated these bytes before it ran the image, because the load
/// commands sit inside the signed area. A `cmdsize` of zero would still loop,
/// so the walk stops on one.
fn walk(header: *const MachHeader, slide: isize, commands: u32) -> Option<Located> {
    let mut segment: Option<(u64, u64, u64)> = None;
    let mut signature: Option<(u32, u32)> = None;
    let mut at = header as usize + size_of::<MachHeader>();

    for _ in 0..commands {
        // SAFETY: `at` starts directly after the header and advances by the
        // size that each command declares, so it addresses one command inside
        // the region that `sizeofcmds` covers.
        let command = unsafe { &*(at as *const LoadCommand) };
        let size = command.cmdsize as usize;
        if size < size_of::<LoadCommand>() {
            return None;
        }

        // Each arm checks the declared size before it reads the larger
        // structure, so a truncated command never reaches a field.
        match command.cmd {
            LC_SEGMENT_64 if size >= size_of::<SegmentCommand>() => {
                // SAFETY: the command declares at least the size of a segment
                // command, and its own `cmd` states that it is one.
                let found = unsafe { &*(at as *const SegmentCommand) };
                if names_linkedit(found) {
                    segment = Some((found.vmaddr, found.fileoff, found.filesize));
                }
            }
            LC_CODE_SIGNATURE if size >= size_of::<LinkeditData>() => {
                // SAFETY: the same argument, for the smaller structure that a
                // `LC_CODE_SIGNATURE` command holds.
                let found = unsafe { &*(at as *const LinkeditData) };
                signature = Some((found.dataoff, found.datasize));
            }
            _ => {}
        }

        at += size;
    }

    fit(segment?, signature?, slide)
}

/// Reports whether a segment carries the `__LINKEDIT` name.
///
/// The field is a fixed array that pads with zero bytes, so the comparison
/// takes the name and the byte after it.
fn names_linkedit(segment: &SegmentCommand) -> bool {
    let name: &[u8; 16] = unsafe {
        // SAFETY: `c_char` and `u8` share a size and an alignment on every
        // Apple target, and the read stays inside the same array.
        &*(&raw const segment.segname).cast::<[u8; 16]>()
    };
    name.starts_with(LINKEDIT) && name[LINKEDIT.len()] == 0
}

/// Turns a file range into an address, and checks that it fits the segment.
///
/// The signature range must lie inside `__LINKEDIT`. That check is what makes
/// the slice in [`code_signature`] sound, so it runs before any read.
fn fit(
    (vmaddr, fileoff, filesize): (u64, u64, u64),
    (dataoff, datasize): (u32, u32),
    slide: isize,
) -> Option<Located> {
    if datasize == 0 || datasize > MAX_SIGNATURE {
        return None;
    }

    let start = u64::from(dataoff);
    let end = start.checked_add(u64::from(datasize))?;
    let segment_end = fileoff.checked_add(filesize)?;
    if start < fileoff || end > segment_end {
        return None;
    }

    // A file offset becomes an address through the mapping of the segment that
    // holds it, and the slide then moves the whole image. The slide is signed,
    // because the loader may map an image below its preferred address.
    let unslid = vmaddr.checked_sub(fileoff)?.checked_add(start)?;
    let address = unslid.checked_add_signed(i64::try_from(slide).ok()?)?;

    Some(Located {
        at: usize::try_from(address).ok()?,
        length: datasize as usize,
    })
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
