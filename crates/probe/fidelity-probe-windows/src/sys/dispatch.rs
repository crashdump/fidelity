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

use fidelity_core::fact::MAX_TARGETS;

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
        // SAFETY: the descriptor names two parallel arrays inside the image,
        // and the walk below states which one it counts and why.
        let count = unsafe { slot_count(base, &descriptor) };
        let table = descriptor.address_table as usize;
        for index in 0..count {
            let thunk = table + index * core::mem::size_of::<u64>();
            // SAFETY: `slot_count` counted this many entries in the array that
            // runs beside this one, and both hold one entry for each import.
            let value: u64 = unsafe { read(base, thunk) };
            let slot = base as u64 + thunk as u64;
            // A zero value is recorded rather than skipped. It is what an
            // attacker writes to end the walk early, and the comparison must
            // see the slot to report that its value moved.
            targets.push(RawTarget { slot, value });
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

/// How many slots the address table of one library holds.
///
/// The lookup table answers this, and the address table must not. Both arrays
/// hold one entry for each import and both end with a zero entry, and they
/// differ in who may write them. The address table is writable by design: the
/// loader fills it, and a hook rewrites it. So an attacker who writes zero to
/// one unused entry ends a walk that counts there, and every slot behind it in
/// the same library leaves the snapshot. `redirected_since` compares what the
/// current snapshot holds, so a redirect among those slots would compare
/// against nothing and report clean. A startup-only import makes that free,
/// because the process never calls the zeroed slot again.
///
/// The lookup table names the same imports in the same order, and nothing
/// writes it after the load. Counting there keeps every slot in the snapshot,
/// and the zeroed entry itself then reports as a target whose value moved.
///
/// An image that carries no lookup table falls back to the address table. A
/// linker that bound its imports may drop it, and a walk that stops early
/// still beats no walk at all. That fallback is what every image got until
/// 2026-08-20, and `MAX_TARGETS` bounds either one.
///
/// # Safety
///
/// The caller states that the descriptor names arrays inside the mapped image.
unsafe fn slot_count(base: *const u8, descriptor: &ImportDescriptor) -> usize {
    let array = if descriptor.lookup_table == 0 {
        descriptor.address_table as usize
    } else {
        descriptor.lookup_table as usize
    };
    let mut count = 0;
    // A corrupt array that never reaches zero would otherwise read the whole
    // address space, so the cap that the snapshot applies also bounds the walk.
    while count < MAX_TARGETS {
        // SAFETY: the array ends with a zero entry, and the test below stops
        // the loop there. The cap above stops it when no zero arrives.
        let entry: u64 = unsafe { read(base, array + count * core::mem::size_of::<u64>()) };
        if entry == 0 {
            break;
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::{ImportDescriptor, read_import_table};

    /// Stores a little-endian `u32` at `offset` in `buffer`.
    fn put32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Stores a little-endian `u64` at `offset` in `buffer`.
    fn put64(buffer: &mut [u8], offset: usize, value: u64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn a_zeroed_address_entry_does_not_hide_a_later_slot() {
        // This is the evasion that the address-table walk missed until
        // 2026-08-20. An attacker writes zero to one unused address-table
        // entry, which ends a walk that counts there, and it redirects a later
        // entry in the same library, which then leaves the snapshot. The walk
        // counts the lookup table instead, so every slot stays, and the zeroed
        // entry itself reports as a target whose value moved.
        //
        // The layout holds one descriptor, a four-entry lookup table with three
        // names, and a four-entry address table whose middle entry is zero. A
        // walk of the address table stops at that zero and records one slot. A
        // walk of the lookup table records three, so the slot behind the zero
        // stays in the snapshot. The test asserts the second answer.
        let mut image = [0u8; 256];

        // The descriptor at offset 0. `name` is any non-zero value, because the
        // walk reads it as a flag and never follows it.
        put32(&mut image, 0x00, 0x40); // lookup_table
        put32(&mut image, 0x0c, 0x01); // name, a non-zero flag
        put32(&mut image, 0x10, 0x80); // address_table
        // Offset 0x14 holds the all-zero terminator descriptor, which the zero
        // fill already wrote, so the walk stops after the first library.

        // The lookup table at 0x40 names three imports and then ends. Nothing
        // writes it after the load, so the walk counts it.
        put64(&mut image, 0x40, 0x1111);
        put64(&mut image, 0x48, 0x2222);
        put64(&mut image, 0x50, 0x3333);

        // The address table at 0x80. The middle entry is the fake terminator
        // that an attacker wrote, and the third entry is the redirect it hides.
        put64(&mut image, 0x80, 0xaaaa);
        put64(&mut image, 0x88, 0x0000);
        put64(&mut image, 0x90, 0xcccc);

        // SAFETY: the buffer holds one descriptor at offset 0 and two parallel
        // arrays inside it, which is what `read_import_table` states it reads.
        let targets = unsafe { read_import_table(image.as_ptr(), 0) };

        // Three slots, because the lookup table named three imports. A walk of
        // the address table would report one, and the slot at 0x90 would be
        // absent, so a redirect there would compare against nothing.
        assert_eq!(targets.targets.len(), 3);
        // The zeroed entry is a recorded slot, not the end of the walk.
        assert_eq!(targets.targets[1].value, 0x0000);
        // The slot behind the zero stays in the snapshot, so a redirect there
        // reports as a value that moved.
        assert_eq!(targets.targets[2].value, 0xcccc);
    }

    #[test]
    fn no_lookup_table_falls_back_to_the_address_table() {
        // A linker that bound its imports may drop the lookup table. The walk
        // then counts the address table, which stops at the first zero. That is
        // the behavior every image got until 2026-08-20, and it still beats no
        // walk at all, so the fallback keeps it.
        let mut image = [0u8; 256];
        put32(&mut image, 0x00, 0x00); // lookup_table absent
        put32(&mut image, 0x0c, 0x01); // name, a non-zero flag
        put32(&mut image, 0x10, 0x80); // address_table
        put64(&mut image, 0x80, 0xaaaa);
        put64(&mut image, 0x88, 0xbbbb);
        // Offset 0x90 holds a zero, which ends the address-table walk.

        // SAFETY: the buffer holds one descriptor whose lookup table is absent,
        // so the walk counts the address table, which this layout supplies.
        let targets = unsafe { read_import_table(image.as_ptr(), 0) };
        assert_eq!(targets.targets.len(), 2);
    }

    #[test]
    fn the_descriptor_layout_matches_the_pe_format() {
        // The reader reads five 32-bit fields, so the struct must be 20 bytes.
        assert_eq!(core::mem::size_of::<ImportDescriptor>(), 20);
    }
}
