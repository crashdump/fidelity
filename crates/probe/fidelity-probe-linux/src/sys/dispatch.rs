//! The bounded dynamic-loader boundary.
//!
//! `dl_iterate_phdr` gives the mapped segments of the main image. This module
//! makes bounded slices from those segments. The safe ELF reader then walks
//! the dynamic array and the jump-slot relocations.

use core::ffi::{c_int, c_void};

use fidelity_core::fact::dispatch::MAX_TARGETS;
use fidelity_formats::elf;

use super::catalog::{Phdr, PhdrInfo, iterate};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

#[cfg(target_arch = "aarch64")]
const JUMP_SLOT: u32 = 1026;
#[cfg(target_arch = "x86_64")]
const JUMP_SLOT: u32 = 7;

struct MainImage {
    found: bool,
    base: u64,
    phdr: *const Phdr,
    phnum: u16,
}

impl Default for MainImage {
    fn default() -> Self {
        Self {
            found: false,
            base: 0,
            phdr: core::ptr::null(),
            phnum: 0,
        }
    }
}

extern "C" fn take_main_image(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the loader gives a live structure and the local output pointer.
    let (name, base, phdr, phnum) = unsafe {
        let info = &*info;
        (info.name, info.base, info.phdr, info.phnum)
    };

    // SAFETY: the loader owns this NUL-terminated name for the callback.
    if !name.is_null() && unsafe { *name } != 0 {
        return 0;
    }

    // SAFETY: `data` points at the live `MainImage` in `read`.
    let image = unsafe { &mut *data.cast::<MainImage>() };
    image.found = true;
    image.base = base;
    image.phdr = phdr;
    image.phnum = phnum;
    1
}

/// One dispatch target, as raw addresses.
pub(crate) struct RawTarget {
    pub(crate) slot: u64,
    pub(crate) value: u64,
}

/// What the loader reports about the dispatch table of the main image.
pub(crate) struct RawTargets {
    pub(crate) targets: Vec<RawTarget>,
    pub(crate) bound: bool,
}

/// Reads the dispatch targets of the main image.
pub(crate) fn read() -> Option<RawTargets> {
    let mut image = MainImage::default();
    // SAFETY: the callback uses only the live local output value.
    unsafe {
        iterate(take_main_image, (&raw mut image).cast::<c_void>());
    }
    if !image.found {
        return None;
    }

    let headers = headers(&image)?;
    let dynamic = segment_bytes(image.base, headers, PT_DYNAMIC, elf::MAX_DYNAMIC_BYTES)?;
    let table = elf::dynamic_table(dynamic)?;
    let relocation_bytes = usize::try_from(table.jump_relocation_bytes()).ok()?;
    let relocations = mapped_bytes(
        table.jump_relocations(),
        relocation_bytes,
        image.base,
        headers,
        elf::MAX_RELOCATION_BYTES,
    )?;
    let slots = elf::jump_slots(relocations, JUMP_SLOT, MAX_TARGETS.saturating_add(1))?;

    let mut targets = Vec::with_capacity(slots.offsets().len());
    for offset in slots.offsets() {
        let slot = image.base.checked_add(*offset)?;
        let value = mapped_bytes(slot, 8, image.base, headers, 8)?;
        let word: [u8; 8] = value.try_into().ok()?;
        targets.push(RawTarget {
            slot,
            value: u64::from_ne_bytes(word),
        });
    }
    Some(RawTargets {
        targets,
        bound: table.is_bound(),
    })
}

fn headers(image: &MainImage) -> Option<&[Phdr]> {
    if image.phdr.is_null() {
        return None;
    }
    let count = usize::from(image.phnum);
    // SAFETY: the loader states that this pointer holds `phnum` headers.
    Some(unsafe { core::slice::from_raw_parts(image.phdr, count) })
}

fn segment_bytes(base: u64, headers: &[Phdr], kind: u32, limit: usize) -> Option<&[u8]> {
    let header = headers.iter().find(|header| header.kind == kind)?;
    let address = base.checked_add(header.vaddr)?;
    let bytes = usize::try_from(header.memsz).ok()?;
    mapped_bytes(address, bytes, base, headers, limit)
}

fn mapped_bytes(
    address: u64,
    bytes: usize,
    base: u64,
    headers: &[Phdr],
    limit: usize,
) -> Option<&[u8]> {
    if bytes > limit {
        return None;
    }
    let bytes_u64 = u64::try_from(bytes).ok()?;
    let end = address.checked_add(bytes_u64)?;
    let mapped = headers
        .iter()
        .filter(|header| header.kind == PT_LOAD)
        .any(|header| {
            let Some(low) = base.checked_add(header.vaddr) else {
                return false;
            };
            let Some(high) = low.checked_add(header.memsz) else {
                return false;
            };
            address >= low && end <= high
        });
    if !mapped {
        return None;
    }
    slice(address, bytes, headers)
}

fn slice(address: u64, bytes: usize, _headers: &[Phdr]) -> Option<&[u8]> {
    let address = usize::try_from(address).ok()?;
    // SAFETY: the caller proves that this range belongs to a mapped segment.
    Some(unsafe { core::slice::from_raw_parts(address as *const u8, bytes) })
}
