//! The Mach-O symbol-pointer boundary.
//!
//! A call to an imported function reads a pointer out of a table, so a hook
//! that rewrites one entry redirects the call without mapping any new code.
//! This module reads that table for the running executable, and the detector
//! compares it against the table that `start()` held.
//!
//! Mach-O binds that table in one of two ways, and only one of them is safe to
//! read. Classic binding, which `LC_DYLD_INFO_ONLY` names, keeps the lazy
//! pointers in `__la_symbol_ptr` and resolves each one on its first call.
//! Chained fixups, which `LC_DYLD_CHAINED_FIXUPS` names, bind every import
//! before the image runs and carry no lazy table at all. So this module answers
//! for a chained image and reports a gap for a classic one, which is the rule
//! that Linux applies to `BIND_NOW`.
//!
//! Measured on macOS 26.5.2 and ARM64 on 2026-08-20. A linker writes chained
//! fixups from a deployment target of macOS 13 or iOS 15, and it writes classic
//! binding below that. A chained Rust image held 73 to 96 pointers in `__got`
//! and no `__la_symbol_ptr`, and none of them moved after start.

use core::ffi::c_char;

/// The load command that names a 64-bit segment.
const LC_SEGMENT_64: u32 = 0x19;

/// The load command that names the chained fixups of an image.
///
/// It carries the `LC_REQ_DYLD` bit, which is `0x8000_0000`. A constant
/// without that bit matches nothing, and the walk then calls every image
/// classic. That cost a measurement on 2026-08-20.
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

/// The file type of a main executable.
const MH_EXECUTE: u32 = 0x2;

/// The mask that selects the type of a section from its flags.
const SECTION_TYPE: u32 = 0xff;

/// The section type that holds pointers which the loader binds at load.
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;

/// The layout of `mach_header_64`.
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

/// The layout of `section_64`, which follows its segment command.
#[repr(C)]
struct Section {
    sectname: [c_char; 16],
    segname: [c_char; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

const _: () = assert!(size_of::<Section>() == 80);

// The dynamic loader reports the images that this process mapped. Apple
// documents all three calls in `<mach-o/dyld.h>`.
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader;
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
}

/// One dispatch target, as the loader holds it.
pub(crate) struct RawTarget {
    pub(crate) slot: u64,
    pub(crate) value: u64,
}

/// The dispatch targets of the main image, and whether the loader bound them.
pub(crate) struct RawTargets {
    pub(crate) targets: Vec<RawTarget>,
    pub(crate) bound: bool,
}

/// Reads the symbol-pointer table of the main executable.
///
/// Returns `None` when no main executable answers, and when the image holds no
/// symbol-pointer section. The caller reports that gap, and it never reads a
/// `None` as a clean result.
#[must_use]
pub(crate) fn read() -> Option<RawTargets> {
    // SAFETY: the call reads a counter that the loader owns, and it takes no
    // pointer.
    let count = unsafe { _dyld_image_count() };

    for index in 0..count {
        // SAFETY: `index` is below the count that the loader just reported, so
        // both calls answer for an image that the loader holds.
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
        // and both reads stay inside the structure that the header names.
        let (filetype, commands) = unsafe { ((*header).filetype, (*header).ncmds) };
        if filetype != MH_EXECUTE {
            continue;
        }
        return walk(header, slide, commands);
    }

    None
}

/// Walks the load commands of the main image for its symbol pointers.
///
/// The kernel validated these bytes before it ran the image, because the load
/// commands sit inside the signed area. A `cmdsize` of zero would still loop,
/// so the walk stops on one.
fn walk(header: *const MachHeader, slide: isize, commands: u32) -> Option<RawTargets> {
    let mut at = (header as usize).checked_add(size_of::<MachHeader>())?;
    let mut targets = Vec::new();
    let mut bound = false;

    for _ in 0..commands {
        // SAFETY: `at` walks the load commands of a mapped image, and each
        // step adds the `cmdsize` that the previous command stated. The read
        // takes the two fields that every load command starts with.
        let command = unsafe { &*(at as *const LoadCommand) };
        let size = command.cmdsize as usize;
        if size < size_of::<LoadCommand>() {
            break;
        }

        if command.cmd == LC_DYLD_CHAINED_FIXUPS {
            bound = true;
        }
        if command.cmd == LC_SEGMENT_64 && size >= size_of::<SegmentCommand>() {
            collect(at, size, slide, &mut targets);
        }

        at = at.checked_add(size)?;
    }

    if targets.is_empty() {
        return None;
    }
    Some(RawTargets { targets, bound })
}

/// Collects every non-lazy symbol pointer of one segment.
fn collect(segment: usize, size: usize, slide: isize, targets: &mut Vec<RawTarget>) {
    // SAFETY: the caller checked that this command is `LC_SEGMENT_64` and that
    // it holds at least a whole `segment_command_64`.
    let nsects = unsafe { (*(segment as *const SegmentCommand)).nsects };

    for index in 0..nsects as usize {
        let Some(offset) = index.checked_mul(size_of::<Section>()) else {
            return;
        };
        let Some(at) = segment
            .checked_add(size_of::<SegmentCommand>())
            .and_then(|start| start.checked_add(offset))
        else {
            return;
        };
        // A malformed `nsects` would walk past the command, so the walk stops
        // at the boundary that `cmdsize` states rather than trusting the count.
        if at.checked_add(size_of::<Section>()) > segment.checked_add(size) {
            return;
        }

        // SAFETY: `at` names a whole `section_64` inside this load command,
        // which the two checks above proved.
        let section = unsafe { &*(at as *const Section) };
        if section.flags & SECTION_TYPE != S_NON_LAZY_SYMBOL_POINTERS {
            continue;
        }

        let Ok(address) = usize::try_from(section.addr) else {
            continue;
        };
        let Some(base) = address.checked_add_signed(slide) else {
            continue;
        };
        let Ok(bytes) = usize::try_from(section.size) else {
            continue;
        };

        for slot in 0..bytes / size_of::<u64>() {
            let Some(at) = slot
                .checked_mul(size_of::<u64>())
                .and_then(|offset| base.checked_add(offset))
            else {
                return;
            };
            // SAFETY: the section header of a mapped segment names an address
            // and a size that the loader mapped, and this stays inside it. The
            // read takes one pointer-sized word, and the address is 8-aligned
            // because a symbol-pointer section holds pointers.
            let value = unsafe { *(at as *const u64) };
            targets.push(RawTarget {
                slot: at as u64,
                value,
            });
        }
    }
}
