//! The bounded Mach-O symbol-pointer boundary.
//!
//! The dynamic loader gives the mapped main image. This module makes a bounded
//! slice from its load commands. The safe Mach-O reader selects the non-lazy
//! symbol-pointer sections and states whether chained fixups bind the image.

use fidelity_core::fact::dispatch::MAX_TARGETS;
use fidelity_formats::macho::dispatch::{MAX_COMMAND_BYTES, dispatch_layout};

use super::regions;

const MH_EXECUTE: u32 = 0x2;

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
#[must_use]
pub(crate) fn read() -> Option<RawTargets> {
    // SAFETY: the call reads the image count and takes no pointer.
    let count = unsafe { _dyld_image_count() };
    for index in 0..count {
        // SAFETY: the index is below the count that the loader reported.
        let (header, slide) = unsafe {
            (
                _dyld_get_image_header(index),
                _dyld_get_image_vmaddr_slide(index),
            )
        };
        if header.is_null() {
            continue;
        }

        // SAFETY: the loader gives a mapped Mach-O header for this image.
        let (filetype, command_count, command_bytes) =
            unsafe { ((*header).filetype, (*header).ncmds, (*header).sizeofcmds) };
        if filetype != MH_EXECUTE {
            continue;
        }
        return targets(header, slide, command_count, command_bytes);
    }
    None
}

fn targets(
    header: *const MachHeader,
    slide: isize,
    command_count: u32,
    command_bytes: u32,
) -> Option<RawTargets> {
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
    let layout = dispatch_layout(commands, command_count)?;

    let mut targets = Vec::new();
    'sections: for section in layout.sections() {
        let address = usize::try_from(section.address()).ok()?;
        let address = address.checked_add_signed(slide)?;
        let bytes = usize::try_from(section.bytes()).ok()?;
        if bytes % size_of::<u64>() != 0 {
            return None;
        }
        let count = bytes / size_of::<u64>();
        let room = MAX_TARGETS.saturating_add(1).saturating_sub(targets.len());
        let take = count.min(room);
        if take == 0 {
            continue;
        }
        let read_bytes = take.checked_mul(size_of::<u64>())?;
        if address % align_of::<u64>() != 0 || !regions::mapped(address as u64, read_bytes) {
            return None;
        }
        // SAFETY: the kernel confirms the aligned range that this reads.
        let values = unsafe { core::slice::from_raw_parts(address as *const u64, take) };
        for (index, value) in values.iter().copied().enumerate() {
            let slot = address.checked_add(index.checked_mul(size_of::<u64>())?)?;
            targets.push(RawTarget {
                slot: slot as u64,
                value,
            });
        }
        if take < count || targets.len() > MAX_TARGETS {
            break 'sections;
        }
    }

    if targets.is_empty() {
        return None;
    }
    Some(RawTargets {
        targets,
        bound: layout.is_bound(),
    })
}
