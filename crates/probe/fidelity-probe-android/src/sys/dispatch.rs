//! The bounded dynamic-loader boundary.
//!
//! Android reads the loaded object that holds Fidelity. The main image is the
//! zygote program, so its table does not dispatch calls from the host. This
//! module makes bounded slices from the object segments. The safe ELF reader
//! then walks the dynamic array and the jump-slot relocations.

use core::ffi::{CStr, c_char, c_int, c_void};

use fidelity_core::fact::dispatch::MAX_TARGETS;
use fidelity_formats::elf;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

#[cfg(target_arch = "aarch64")]
const JUMP_SLOT: u32 = 1026;
#[cfg(target_arch = "x86_64")]
const JUMP_SLOT: u32 = 7;

static ANCHOR: u8 = 0x1d;

#[repr(C)]
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[repr(C)]
struct PhdrInfo {
    base: u64,
    name: *const c_char,
    phdr: *const Phdr,
    phnum: u16,
}

unsafe extern "C" {
    fn dl_iterate_phdr(
        callback: extern "C" fn(*mut PhdrInfo, usize, *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;
}

struct OwnImage {
    anchor: u64,
    found: bool,
    base: u64,
    name: *const c_char,
    phdr: *const Phdr,
    phnum: u16,
}

impl OwnImage {
    fn seeking(anchor: u64) -> Self {
        Self {
            anchor,
            found: false,
            base: 0,
            name: core::ptr::null(),
            phdr: core::ptr::null(),
            phnum: 0,
        }
    }
}

extern "C" fn take_own_image(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the loader gives a live structure and the local output pointer.
    let (name, base, phdr, phnum) = unsafe {
        let info = &*info;
        (info.name, info.base, info.phdr, info.phnum)
    };
    if phdr.is_null() {
        return 0;
    }

    // SAFETY: `data` points at the live `OwnImage` in `find`.
    let image = unsafe { &mut *data.cast::<OwnImage>() };
    // SAFETY: the loader states that this pointer holds `phnum` headers.
    let headers = unsafe { core::slice::from_raw_parts(phdr, usize::from(phnum)) };
    if !holds(image.anchor, base, headers) {
        return 0;
    }

    image.found = true;
    image.base = base;
    image.name = name;
    image.phdr = phdr;
    image.phnum = phnum;
    1
}

fn holds(address: u64, base: u64, headers: &[Phdr]) -> bool {
    headers
        .iter()
        .filter(|header| header.kind == PT_LOAD)
        .any(|header| {
            let Some(low) = base.checked_add(header.vaddr) else {
                return false;
            };
            let Some(high) = low.checked_add(header.memsz) else {
                return false;
            };
            address >= low && address < high
        })
}

fn find() -> Option<OwnImage> {
    let anchor = (&raw const ANCHOR) as usize as u64;
    let mut image = OwnImage::seeking(anchor);
    // SAFETY: the callback uses only the live local output value.
    unsafe {
        dl_iterate_phdr(take_own_image, (&raw mut image).cast::<c_void>());
    }
    if image.found { Some(image) } else { None }
}

/// One dispatch target, as raw addresses.
pub(crate) struct RawTarget {
    pub(crate) slot: u64,
    pub(crate) value: u64,
}

/// What the loader reports about the dispatch table of the image.
pub(crate) struct RawTargets {
    pub(crate) targets: Vec<RawTarget>,
    pub(crate) bound: bool,
}

/// Reads the dispatch targets of the object that holds Fidelity.
pub(crate) fn read() -> Option<RawTargets> {
    let image = find()?;
    let headers = headers(&image)?;
    let dynamic = segment_bytes(image.base, headers, PT_DYNAMIC, elf::MAX_DYNAMIC_BYTES)?;
    let table = elf::dynamic_table(dynamic)?;
    let relocation_bytes = usize::try_from(table.jump_relocation_bytes()).ok()?;
    let address = image.base.checked_add(table.jump_relocations())?;
    let relocations = mapped_bytes(
        address,
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

/// The path of the object that holds Fidelity.
pub(crate) fn image_path() -> Option<String> {
    let image = find()?;
    if image.name.is_null() {
        return None;
    }
    // SAFETY: the loader owns this NUL-terminated name while the object lives.
    unsafe { CStr::from_ptr(image.name) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn headers(image: &OwnImage) -> Option<&[Phdr]> {
    if image.phdr.is_null() {
        return None;
    }
    // SAFETY: the loader states that this pointer holds `phnum` headers.
    Some(unsafe { core::slice::from_raw_parts(image.phdr, usize::from(image.phnum)) })
}

fn segment_bytes<'a>(base: u64, headers: &'a [Phdr], kind: u32, limit: usize) -> Option<&'a [u8]> {
    let header = headers.iter().find(|header| header.kind == kind)?;
    let address = base.checked_add(header.vaddr)?;
    let bytes = usize::try_from(header.memsz).ok()?;
    mapped_bytes(address, bytes, base, headers, limit)
}

fn mapped_bytes<'a>(
    address: u64,
    bytes: usize,
    base: u64,
    headers: &'a [Phdr],
    limit: usize,
) -> Option<&'a [u8]> {
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

fn slice<'a>(address: u64, bytes: usize, _headers: &'a [Phdr]) -> Option<&'a [u8]> {
    let address = usize::try_from(address).ok()?;
    // SAFETY: the caller proves that this range belongs to a mapped segment.
    Some(unsafe { core::slice::from_raw_parts(address as *const u8, bytes) })
}
