//! The dynamic-loader boundary.
//!
//! `dl_iterate_phdr` names every loaded object and gives its base address and
//! its program headers. The `PT_DYNAMIC` segment of an object names its
//! jump-slot relocation table, and each entry of that table names one dispatch
//! target. Reading the target gives the address the call reaches now. Linux
//! reads the same tables, and its own `sys/dispatch.rs` holds that reader.
//!
//! Android picks the object by another rule, and two measurements decide it.
//! Both ran on Android 16, API 36, and ARM64 on 2026-08-20.
//!
//! An application forks from zygote, so its main image is
//! `/system/bin/app_process64`. Every application on the device runs that one
//! system binary, and the calls of the host never reach its table. The code of
//! the host sits in a library that the application loads, and that library
//! holds the table an attacker rewrites to intercept the calls of the host.
//!
//! Bionic also names an object differently from glibc. It gives the full path
//! of the main executable, and it reports the linker first, so the empty name
//! that Linux reads as the main image never appears here.
//!
//! This module therefore reads the object that holds the code of Fidelity. It
//! finds that object by the address of [`ANCHOR`], which the compiler puts in
//! the image that it links this crate into. A host links Fidelity into its own
//! library, so that image is the library of the host.
//!
//! Checked against `man dl_iterate_phdr`, `elf.h`, and the System V ABI on
//! 2026-08-20. The v1 floor names ARM64 and `x86_64`, and this module covers
//! both.

use core::ffi::{CStr, c_char, c_int, c_void};

/// The program headers that this module reads.
const PT_LOAD: u32 = 1;
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

/// One byte of this crate, and the address that selects the object below.
///
/// The value carries no meaning. Only the address does: the object that holds
/// this byte is the object that the linker built this crate into.
static ANCHOR: u8 = 0x1d;

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

/// The leading fields of `struct dl_phdr_info`. Bionic declares more fields
/// after these, and it never moves these, so this prefix is stable.
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

/// The object that holds this crate, as the callback found it.
struct OwnImage {
    anchor: u64,
    found: bool,
    base: u64,
    name: *const c_char,
    phdr: *const Phdr,
    phnum: u16,
}

// The empty value below is written by hand, and it must stay that way. The
// workspace states Rust 1.85, and `Default` for a raw pointer arrived in 1.88,
// so a derive here builds on a newer toolchain and breaks the version that
// `docs/plan/06-delivery.md` makes normative. The Linux probe carries the same
// note, because the `msrv` control found it there first.
impl OwnImage {
    /// The empty value, which carries the address that selects the object.
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

/// Stops at the object whose mapped range holds the anchor address.
///
/// A non-zero return ends the iteration, so the callback keeps the first
/// object it accepts. One address sits in one object, so there is only one.
extern "C" fn take_own_image(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the loader passes a live `dl_phdr_info` and our own `data`
    // pointer, which points at the `OwnImage` below. The read touches only the
    // stable prefix that `PhdrInfo` declares.
    let (name, base, phdr, phnum) = unsafe {
        let info = &*info;
        (info.name, info.base, info.phdr, info.phnum)
    };
    if phdr.is_null() {
        return 0;
    }

    // SAFETY: `data` is the `OwnImage` that `find` passed, and it is a live
    // local for the whole call.
    let image = unsafe { &mut *data.cast::<OwnImage>() };
    if !holds(image.anchor, base, phdr, phnum) {
        return 0;
    }

    image.found = true;
    image.base = base;
    image.name = name;
    image.phdr = phdr;
    image.phnum = phnum;
    1
}

/// Whether the loaded segments of one object hold an address.
///
/// The check reads `p_memsz` rather than `p_filesz`, because a static that no
/// file backs sits in the part that only the memory size covers.
fn holds(address: u64, base: u64, phdr: *const Phdr, phnum: u16) -> bool {
    for index in 0..usize::from(phnum) {
        // SAFETY: `dl_iterate_phdr` states that `phdr` points at `phnum`
        // headers, so every index below `phnum` is inside that array.
        let header = unsafe { &*phdr.add(index) };
        if header.kind != PT_LOAD {
            continue;
        }
        let Some(low) = base.checked_add(header.vaddr) else {
            continue;
        };
        let Some(high) = low.checked_add(header.memsz) else {
            continue;
        };
        if address >= low && address < high {
            return true;
        }
    }
    false
}

/// Finds the object that holds the code of this crate.
fn find() -> Option<OwnImage> {
    let anchor = (&raw const ANCHOR) as usize as u64;
    let mut image = OwnImage::seeking(anchor);
    // SAFETY: the callback reads only the live `image` through `data`, and it
    // holds no reference past its own return. `dl_iterate_phdr` runs the
    // callback synchronously on this thread.
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

/// Reads the dispatch targets of the object that holds this crate.
///
/// Returns `None` when the loader names no such object, or when that object
/// carries no jump-slot table. Neither is an error: a static image holds no
/// such table.
pub(crate) fn read() -> Option<RawTargets> {
    let image = find()?;
    let dynamic = dynamic_array(image.base, image.phdr, image.phnum)?;
    read_table(image.base, dynamic)
}

/// The path that the loader holds for the object that this crate sits in.
///
/// The instrumented harness reads this, because an application forks from
/// zygote and its main image is a system binary that no host controls. Only a
/// comparison against the library that the application loaded states that the
/// probe reads the table of the host.
pub(crate) fn image_path() -> Option<String> {
    let image = find()?;
    if image.name.is_null() {
        return None;
    }
    // SAFETY: `name` is the NUL-terminated string of the loader, and the
    // loader keeps it for the life of the object. The object holds this code,
    // so it stays loaded for the whole call.
    let path = unsafe { CStr::from_ptr(image.name) };
    path.to_str().ok().map(str::to_owned)
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

    // Bionic leaves the dynamic array as the linker wrote it, so every address
    // in it stays relative to the base of the object. Its own linker adds the
    // load bias each time it reads one, and this reader does the same. glibc
    // rewrites those entries in place instead, which is why the Linux probe
    // reads the value directly and this one must not.
    let table = base.checked_add(table)?;

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
