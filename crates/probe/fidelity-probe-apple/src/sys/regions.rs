//! The Mach virtual-memory boundary.
//!
//! The module walks the top-level executable regions of this task, and it does
//! not descend into a submap. That choice is the whole design, and it comes
//! from a measurement rather than from taste.
//!
//! `mach_vm_region_recurse` descends, and the dyld shared cache is a submap of
//! about 1.7 GB. Measured on macOS 26 and ARM64: the deep walk finds 17
//! executable regions in 87 passes and costs **27 ms**, because one call walks
//! the whole shared cache. The top-level walk finds 1 region in 54 passes and
//! costs **36 us**. Both see an injected mapping arrive.
//!
//! A baseline compares one snapshot against another, so a region that never
//! changes buys nothing. Injected code arrives as a top-level entry, because a
//! caller cannot map into the shared cache submap. The cheap walk therefore
//! loses no evidence, and it keeps a worker cycle inside the performance
//! budget. See `docs/plan/07-state-and-budgets.md`.

use std::ffi::c_void;

/// The protection bit that marks a region as executable.
const VM_PROT_EXECUTE: i32 = 0x4;

/// Ask for the 64-bit basic form of the region information.
const VM_REGION_BASIC_INFO_64: i32 = 9;

/// The size of that form, in 32-bit words.
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

/// The call succeeded.
const KERN_SUCCESS: i32 = 0;

/// How many passes the walk makes before it gives up.
///
/// The bound stops a malformed answer from looping. A process holds far fewer
/// regions than this, and `fidelity_core::MAX_REGIONS` bounds what a caller
/// keeps.
const MAX_PASSES: usize = 100_000;

/// The layout of `vm_region_basic_info_data_64_t`.
///
/// The structure packs to 4 bytes: its 64-bit `offset` sits at byte 20, and
/// not at byte 24. A mirror that lets the compiler align that field reads
/// every later field from the wrong place.
///
/// Measured against the macOS SDK on 2026-08-09: 36 bytes, and 9 words. The
/// two assertions below fail the build if either ever changes.
#[repr(C, packed(4))]
#[derive(Default)]
struct BasicInfo {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    shared: i32,
    reserved: i32,
    offset: u64,
    behavior: i32,
    user_wired_count: u16,
}

/// The kernel writes the whole structure, so its size must match the header.
const _: () = assert!(size_of::<BasicInfo>() == 36);

/// The count states the size in 32-bit words, so the two must agree.
const _: () = assert!(VM_REGION_BASIC_INFO_COUNT_64 as usize * 4 == size_of::<BasicInfo>());

unsafe extern "C" {
    fn mach_task_self() -> u32;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut c_void,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
}

/// One executable region, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Region {
    /// The first address of the region.
    pub(crate) start: u64,
    /// The address after the region.
    pub(crate) end: u64,
}

/// Walks the top-level executable regions of this task, in address order.
///
/// # Errors
///
/// Returns the reason the walk failed. A process always executes its own code,
/// so an empty answer means the walk broke, and Fidelity never reports that as
/// a clean result.
pub(crate) fn executable() -> Result<Vec<Region>, &'static str> {
    let mut found = Vec::new();
    let mut address: u64 = 0;
    let mut passes = 0_usize;

    while passes < MAX_PASSES {
        passes += 1;
        let mut size: u64 = 0;
        let mut info = BasicInfo::default();
        let mut count = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object: u32 = 0;

        // SAFETY: every pointer refers to a live local of this call. `info`
        // has the layout the kernel writes for this flavor, and `count` states
        // its length in 32-bit words, so the kernel writes inside it. The task
        // port is this task, which always exists.
        let result = unsafe {
            mach_vm_region(
                mach_task_self(),
                &raw mut address,
                &raw mut size,
                VM_REGION_BASIC_INFO_64,
                (&raw mut info).cast::<c_void>(),
                &raw mut count,
                &raw mut object,
            )
        };

        if result != KERN_SUCCESS || size == 0 {
            // The walk ends when no region sits at or above the address.
            break;
        }

        // A packed field needs a copy, because a reference to it would not be
        // aligned.
        let protection = info.protection;
        if protection & VM_PROT_EXECUTE != 0 {
            found.push(Region {
                start: address,
                end: address.saturating_add(size),
            });
        }

        let Some(next) = address.checked_add(size) else {
            break;
        };
        address = next;
    }

    if found.is_empty() {
        return Err("the kernel reported no executable region for this task");
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::executable;

    #[test]
    fn the_walk_finds_the_executable_code_of_this_task() {
        // The clean control for the boundary. A process always executes its
        // own code, so an empty answer means the walk broke.
        assert!(!executable().unwrap_or_default().is_empty());
    }

    #[test]
    fn every_region_ends_after_it_starts() {
        for region in executable().unwrap_or_default() {
            assert!(region.end > region.start, "{region:?}");
        }
    }

    #[test]
    fn the_walk_reports_regions_in_address_order() {
        let regions = executable().unwrap_or_default();
        assert!(
            regions
                .windows(2)
                .all(|pair| pair[0].start <= pair[1].start)
        );
    }

    #[test]
    fn two_walks_of_an_unchanged_task_agree() {
        // The property the detector depends on. A walk that returned a moving
        // answer would report a finding on every cycle.
        //
        // The pair has to come from a quiet moment, and a test runner is not
        // quiet: another test can map code between the two walks. Measured
        // under the address sanitizer on 2026-08-09. A walk that really moved
        // would never produce an agreeing pair, so the bound still fails one.
        const ATTEMPTS: usize = 8;

        let agreed = (0..ATTEMPTS)
            .any(|_| executable().unwrap_or_default() == executable().unwrap_or_default());
        assert!(agreed, "no pair of walks agreed, so the walk itself moves");
    }
}
