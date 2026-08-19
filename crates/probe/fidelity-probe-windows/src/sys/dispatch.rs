//! The import-table boundary.
//!
//! `GetModuleHandleW(NULL)` answers with the base of the main module, which is
//! the executable that started the process. The PE headers there name the
//! import table, and each entry of that table is a dispatch target. Reading the
//! entry gives the address the imported call reaches now.
//!
//! Windows resolves the static import table at load, before the entry point
//! runs, so every entry holds its final value from the start of the process. A
//! delay-load import is a separate table that this module does not read, so no
//! entry here moves on a first call. Measured in the QEMU guest on 2026-08-19:
//! a Rust main image holds 71 import entries, none outside a loaded image and
//! none that moved over three seconds.
//!
//! Checked against the PE format and `winnt.h` on 2026-08-19. The v1 floor
//! names ARM64 and `x86_64`, and both use the PE32+ optional header.

use core::ffi::c_void;

/// `IMAGE_DOS_SIGNATURE`, the `MZ` at the front of every module.
const DOS_SIGNATURE: u16 = 0x5a4d;

/// `IMAGE_NT_SIGNATURE`, the `PE\0\0` that the DOS stub points at.
const NT_SIGNATURE: u32 = 0x0000_4550;

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`, the PE32+ optional header. The v1 floor is
/// 64-bit, so a 32-bit image is out of scope and reports nothing.
const OPTIONAL_MAGIC_64: u16 = 0x20b;

/// Where `e_lfanew` sits in the DOS header, as a byte offset.
const E_LFANEW: usize = 60;

/// Where the optional header starts after the NT signature: four signature
/// bytes and a twenty-byte file header.
const OPTIONAL_FROM_NT: usize = 24;

/// Where the data directory sits in the PE32+ optional header, as a byte
/// offset from the start of that header.
const DATA_DIRECTORY: usize = 112;

/// `IMAGE_DIRECTORY_ENTRY_IMPORT`, the directory that names the import table.
const IMPORT_DIRECTORY: usize = 1;

/// The magic of the optional header, as a byte offset from its start.
const OPTIONAL_MAGIC: usize = 0;

/// `IMAGE_IMPORT_DESCRIPTOR`, one entry per imported library.
#[repr(C)]
#[derive(Clone, Copy)]
struct ImportDescriptor {
    lookup_table: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    address_table: u32,
}

unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

/// One dispatch target, as raw addresses.
pub(crate) struct RawTarget {
    pub(crate) slot: u64,
    pub(crate) value: u64,
}

/// What the loader reports about the import table of the main module.
pub(crate) struct RawTargets {
    pub(crate) targets: Vec<RawTarget>,
    pub(crate) bound: bool,
}

/// Reads a value of type `T` from `base + offset`.
///
/// # Safety
///
/// The caller states that `base + offset` sits inside the mapped image and
/// holds a valid `T`. Every call below reads a field of the image's own PE
/// headers or import table, which the loader mapped and wrote.
unsafe fn read<T: Copy>(base: *const u8, offset: usize) -> T {
    // SAFETY: the caller guarantees the range is inside the mapped image. The
    // read is unaligned, because a PE field carries no alignment promise.
    unsafe { base.add(offset).cast::<T>().read_unaligned() }
}

/// Reads the dispatch targets of the main module.
///
/// Returns `None` when the module names no import table, which a static image
/// with no imports does. That is a gap in coverage, and never a finding.
pub(crate) fn read_targets() -> Option<RawTargets> {
    // SAFETY: a null name asks for the module that started the process, which
    // always exists, so the call returns its base.
    let base = unsafe { GetModuleHandleW(core::ptr::null()) }.cast::<u8>();
    if base.is_null() {
        return None;
    }

    // SAFETY: the loader maps the DOS header, the NT headers, and the optional
    // header at the front of the image, so every field below is inside the
    // mapped image. Each read states the offset that `winnt.h` fixes.
    unsafe {
        if read::<u16>(base, 0) != DOS_SIGNATURE {
            return None;
        }
        let Ok(nt) = usize::try_from(read::<i32>(base, E_LFANEW)) else {
            // A negative `e_lfanew` names no header inside the image.
            return None;
        };
        if read::<u32>(base, nt) != NT_SIGNATURE {
            return None;
        }
        let optional = nt + OPTIONAL_FROM_NT;
        if read::<u16>(base, optional + OPTIONAL_MAGIC) != OPTIONAL_MAGIC_64 {
            // A 32-bit image is out of the v1 floor, so this states a gap.
            return None;
        }

        let directory = optional + DATA_DIRECTORY + IMPORT_DIRECTORY * 8;
        let import_rva = read::<u32>(base, directory) as usize;
        if import_rva == 0 {
            return None;
        }

        Some(read_import_table(base, import_rva))
    }
}

/// Walks the import descriptors and reads every address-table entry.
///
/// # Safety
///
/// The caller states that `import_rva` names the import table inside the mapped
/// image.
unsafe fn read_import_table(base: *const u8, import_rva: usize) -> RawTargets {
    let mut targets = Vec::new();
    let mut cursor = import_rva;
    loop {
        // SAFETY: the import table ends with an all-zero descriptor, and the
        // `name == 0` test below stops the loop there, so the cursor stays
        // inside the table.
        let descriptor: ImportDescriptor = unsafe { read(base, cursor) };
        if descriptor.name == 0 && descriptor.address_table == 0 {
            break;
        }
        let mut thunk = descriptor.address_table as usize;
        loop {
            // SAFETY: the address table of one library ends with a zero entry,
            // and the test below stops the loop there.
            let value: u64 = unsafe { read(base, thunk) };
            if value == 0 {
                break;
            }
            let slot = base as u64 + thunk as u64;
            targets.push(RawTarget { slot, value });
            thunk += core::mem::size_of::<u64>();
        }
        cursor += core::mem::size_of::<ImportDescriptor>();
    }

    // The static import table is always fully bound at load, so a later change
    // to an entry arrived from outside.
    RawTargets {
        targets,
        bound: true,
    }
}
