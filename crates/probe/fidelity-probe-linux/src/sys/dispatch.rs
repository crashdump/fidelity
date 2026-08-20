//! The dynamic-loader boundary.
//!
//! `dl_iterate_phdr` names every loaded object and gives its base address and
//! its program headers. The main image is the object with an empty name. Its
//! `PT_DYNAMIC` segment names the jump-slot relocation table, and each entry
//! of that table names one dispatch target. Reading the target gives the
//! address the call reaches now.
//!
//! Checked against `man dl_iterate_phdr`, `elf.h`, and the System V ABI on
//! 2026-08-19. The v1 floor names ARM64 and `x86_64`, and this module covers
//! both.

use core::ffi::{c_char, c_int, c_void};

/// `PT_DYNAMIC`, the program header that names the dynamic array.
const PT_DYNAMIC: u32 = 2;

/// The dynamic-array tags that this module reads, from the System V ABI.
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

/// `DT_RELA`, the only relocation form that carries an addend, and the only
/// one this module reads.
const DT_RELA: u64 = 7;

/// `DF_BIND_NOW` in `DT_FLAGS`, and `DF_1_NOW` in `DT_FLAGS_1`. Either one
/// states that the loader bound the whole table before the process ran.
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

/// The jump-slot relocation type, per architecture. The low word of `r_info`
/// holds it.
#[cfg(target_arch = "aarch64")]
const JUMP_SLOT: u32 = 1026;
#[cfg(target_arch = "x86_64")]
const JUMP_SLOT: u32 = 7;

/// `Elf64_Phdr`, the program header.
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

/// `Elf64_Dyn`, one entry of the dynamic array.
#[repr(C)]
struct Dyn {
    tag: i64,
    value: u64,
}

/// `Elf64_Rela`, one relocation with an addend.
#[repr(C)]
struct Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

/// The leading fields of `struct dl_phdr_info`. The structure grows in later
/// glibc, and every added field sits after these, so this prefix is stable.
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

/// The main image, as the callback found it.
struct MainImage {
    found: bool,
    base: u64,
    phdr: *const Phdr,
    phnum: u16,
}

// The workspace states Rust 1.85, and `Default` for a raw pointer arrived in
// 1.88. A derive here therefore built on this machine and broke the version
// that `docs/plan/06-delivery.md` makes normative, on the two Linux targets
// alone. The `msrv` control found it. Write the empty value by hand instead.
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

/// Stops at the first object with an empty name, which is the main program.
///
/// A non-zero return ends the iteration, so the callback runs for the main
/// image alone.
extern "C" fn take_main_image(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the loader passes a live `dl_phdr_info` and our own `data`
    // pointer, which points at the `MainImage` below. The read touches only
    // the stable prefix that `PhdrInfo` declares.
    let (name, base, phdr, phnum) = unsafe {
        let info = &*info;
        (info.name, info.base, info.phdr, info.phnum)
    };

    // SAFETY: `name` is the loader's own NUL-terminated string, and the main
    // program is the object whose name is empty. Only its first byte is read.
    let is_main = name.is_null() || unsafe { *name } == 0;
    if !is_main {
        return 0;
    }

    // SAFETY: `data` is the `MainImage` that `read` passed, and it is a live
    // local for the whole call.
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
///
/// Returns `None` when the loader names no main image or the main image
/// carries no jump-slot table. Neither is an error: a static image holds no
/// such table.
pub(crate) fn read() -> Option<RawTargets> {
    let mut image = MainImage::default();
    // SAFETY: the callback reads only the live `image` through `data`, and it
    // holds no reference past its own return. `dl_iterate_phdr` runs the
    // callback synchronously on this thread.
    unsafe {
        dl_iterate_phdr(take_main_image, (&raw mut image).cast::<c_void>());
    }
    if !image.found || image.phdr.is_null() {
        return None;
    }

    let dynamic = dynamic_array(image.base, image.phdr, image.phnum)?;
    read_table(image.base, dynamic)
}

/// Finds the dynamic array of the image from its program headers.
fn dynamic_array(base: u64, phdr: *const Phdr, phnum: u16) -> Option<*const Dyn> {
    for index in 0..usize::from(phnum) {
        // SAFETY: `dl_iterate_phdr` states that `phdr` points at `phnum`
        // headers, so every index below `phnum` is inside that array.
        let header = unsafe { &*phdr.add(index) };
        if header.kind == PT_DYNAMIC {
            let address = base.checked_add(header.vaddr)?;
            return Some(address as *const Dyn);
        }
    }
    None
}

/// Walks the dynamic array and reads the jump-slot table it names.
fn read_table(base: u64, dynamic: *const Dyn) -> Option<RawTargets> {
    let mut table = 0_u64;
    let mut bytes = 0_u64;
    let mut form = 0_u64;
    let mut bound = false;

    let mut cursor = dynamic;
    loop {
        // SAFETY: the dynamic array ends with a `DT_NULL` entry, which stops
        // the loop before the cursor leaves the array.
        let entry = unsafe { &*cursor };
        match entry.tag {
            DT_NULL => break,
            DT_JMPREL => table = entry.value,
            DT_PLTRELSZ => bytes = entry.value,
            DT_PLTREL => form = entry.value,
            DT_BIND_NOW => bound = true,
            DT_FLAGS if entry.value & DF_BIND_NOW != 0 => bound = true,
            DT_FLAGS_1 if entry.value & DF_1_NOW != 0 => bound = true,
            _ => {}
        }
        // SAFETY: the cursor stays inside the array, because the loop breaks at
        // the `DT_NULL` terminator that the loader writes.
        cursor = unsafe { cursor.add(1) };
    }

    // Only the addend form carries a target this reader understands, and a
    // table of zero size names none.
    if table == 0 || bytes == 0 || form != DT_RELA {
        return None;
    }

    let entry_bytes = core::mem::size_of::<Rela>() as u64;
    let Ok(count) = usize::try_from(bytes / entry_bytes) else {
        return None;
    };
    let relocations = table as *const Rela;
    let mut targets = Vec::new();
    for index in 0..count {
        // SAFETY: `bytes` is the size of the table in bytes, so `count` is the
        // number of `Rela` entries, and every index below it is inside the
        // table that the loader mapped.
        let relocation = unsafe { &*relocations.add(index) };
        // The low word of `r_info` holds the type. Comparing in `u64` keeps
        // the mask and needs no cast.
        if relocation.info & 0xffff_ffff != u64::from(JUMP_SLOT) {
            continue;
        }
        let slot = base.checked_add(relocation.offset)?;
        // SAFETY: the loader mapped the slot as part of the image, and it holds
        // one pointer. The read takes that pointer and nothing around it.
        let value = unsafe { *(slot as *const u64) };
        targets.push(RawTarget { slot, value });
    }

    Some(RawTargets { targets, bound })
}
