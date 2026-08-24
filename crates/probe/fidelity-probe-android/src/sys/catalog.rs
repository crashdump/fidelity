//! The bounded dynamic-loader catalog.

use core::ffi::{c_char, c_int, c_void};

use fidelity_core::fact::MAX_REGIONS;

const PT_LOAD: u32 = 1;

#[repr(C)]
pub(crate) struct Phdr {
    pub(crate) kind: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) vaddr: u64,
    pub(crate) paddr: u64,
    pub(crate) filesz: u64,
    pub(crate) memsz: u64,
    pub(crate) align: u64,
}

#[repr(C)]
pub(crate) struct PhdrInfo {
    pub(crate) base: u64,
    pub(crate) name: *const c_char,
    pub(crate) phdr: *const Phdr,
    pub(crate) phnum: u16,
}

unsafe extern "C" {
    fn dl_iterate_phdr(
        callback: extern "C" fn(*mut PhdrInfo, usize, *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;
}

/// Visits the images that the dynamic loader lists.
pub(crate) unsafe fn iterate(
    callback: extern "C" fn(*mut PhdrInfo, usize, *mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the caller supplies a callback and data pointer that agree.
    unsafe { dl_iterate_phdr(callback, data) }
}

#[derive(Default)]
struct Catalog {
    ranges: Vec<(u64, u64)>,
    failed: bool,
}

extern "C" fn take_ranges(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the loader gives a live structure and the local output pointer.
    let (base, phdr, phnum) = unsafe {
        let info = &*info;
        (info.base, info.phdr, info.phnum)
    };
    // SAFETY: `data` points at the live `Catalog` in `read`.
    let catalog = unsafe { &mut *data.cast::<Catalog>() };
    if phdr.is_null() || phnum == 0 {
        catalog.failed = true;
        return 1;
    }
    // SAFETY: the loader states that this pointer holds `phnum` headers.
    let headers = unsafe { core::slice::from_raw_parts(phdr, usize::from(phnum)) };
    for header in headers.iter().filter(|header| header.kind == PT_LOAD) {
        let Some(raw_start) = base.checked_add(header.vaddr) else {
            catalog.failed = true;
            return 1;
        };
        let Some(raw_end) = raw_start.checked_add(header.memsz) else {
            catalog.failed = true;
            return 1;
        };
        let Some((start, end)) = aligned(raw_start, raw_end, header.align) else {
            catalog.failed = true;
            return 1;
        };
        if catalog.ranges.len() >= MAX_REGIONS {
            catalog.failed = true;
            return 1;
        }
        catalog.ranges.push((start, end));
    }
    0
}

fn aligned(start: u64, end: u64, alignment: u64) -> Option<(u64, u64)> {
    if alignment <= 1 {
        return Some((start, end));
    }
    if !alignment.is_power_of_two() {
        return None;
    }
    let mask = alignment.checked_sub(1)?;
    let start = start & !mask;
    let end = end.checked_add(mask)? & !mask;
    Some((start, end))
}

/// Reads each load range that the dynamic loader lists.
pub(crate) fn read() -> Result<Vec<(u64, u64)>, &'static str> {
    let mut catalog = Catalog::default();
    // SAFETY: the callback uses only the live local output value.
    unsafe {
        iterate(take_ranges, (&raw mut catalog).cast::<c_void>());
    }
    if catalog.failed {
        return Err("the dynamic-loader catalog is invalid or reached its bound");
    }
    if catalog.ranges.is_empty() {
        return Err("the dynamic-loader catalog reported no load range");
    }
    Ok(catalog.ranges)
}
