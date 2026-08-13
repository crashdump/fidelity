//! The Win32 virtual-memory boundary.
//!
//! One walk answers both the `baseline` capability and the `injection`
//! capability, in the same way that one read of `/proc/self/maps` answers both
//! on Linux. `VirtualQuery` reports one run of pages that share every
//! attribute, so a walk steps from the base address of one run to the next.
//!
//! Windows states the origin of a region directly, in the `Type` field, and no
//! other supported platform does. Linux infers the origin from a path, and
//! Apple cannot answer it at all. That field is what makes the structural
//! question in
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! cheap here.

use core::ffi::c_void;

/// The four protection values that allow execution.
///
/// Each one is a distinct value rather than a bit, so the mask covers the
/// range that holds all four. A modifier such as `PAGE_GUARD` sits above this
/// mask, so a guarded executable page still reads as executable.
const EXECUTE: u32 = 0xF0;

/// The two protection values that allow execution and a write.
///
/// `PAGE_EXECUTE_READWRITE` is `0x40`, and `PAGE_EXECUTE_WRITECOPY` is `0x80`.
/// A copy-on-write page counts, because a write to it succeeds and leaves the
/// private copy executable.
const EXECUTE_WRITE: u32 = 0xC0;

/// The pages hold physical storage, so the other fields mean something.
///
/// Microsoft states that `Protect` and `Type` are undefined for a free region
/// and that `Protect` is undefined for a reserved one, so the walk reads
/// neither field until it sees this state.
const MEM_COMMIT: u32 = 0x1000;

/// The pages are a view of an image section, so a module accounts for them.
const MEM_IMAGE: u32 = 0x100_0000;

/// The pages are a view of a section that is not an image.
///
/// A section that a file backs is accounted, and a section that the page file
/// backs is not. Only [`super::psapi::mapped_file`] separates the two.
const MEM_MAPPED: u32 = 0x4_0000;

/// How many passes the walk makes before it gives up.
///
/// The bound stops a malformed answer from looping. A process holds far fewer
/// runs than this, and `fidelity_core::MAX_REGIONS` bounds what a caller keeps.
const MAX_PASSES: usize = 100_000;

/// The layout of `MEMORY_BASIC_INFORMATION`.
///
/// Checked against the winnt.h reference on 2026-08-13. `PartitionId` arrived
/// in Windows 10 19H1, and it costs no size: it sits in the padding that
/// followed `AllocationProtect`, so a build against an older header produces
/// the same 48 bytes. The assertion below holds either reading.
///
/// The v1 floor names two architectures, ARM64 and `x86_64`, and both are
/// 64-bit, so the size is a constant rather than a target condition.
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

/// The operating system writes the whole structure, so its size must match.
const _: () = assert!(size_of::<MemoryBasicInformation>() == 48);

unsafe extern "system" {
    fn VirtualQuery(
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

/// One executable region, as the operating system reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Region {
    /// The first address of the region.
    pub(crate) start: u64,
    /// The address after the region.
    pub(crate) end: u64,
    /// Whether the region is writable as well as executable.
    pub(crate) writable: bool,
    /// Whether an image section holds this region.
    ///
    /// A loader maps a module as an image, so this is the cheap half of the
    /// origin question. The walk answers the other half for a mapped section.
    pub(crate) image: bool,
    /// Whether the region is a view of a section that is not an image.
    pub(crate) mapped: bool,
}

impl Region {
    /// Whether a file on disk accounts for this region.
    ///
    /// An image always has one. A mapped section has one only when the
    /// operating system names a file for it, and the page file backs the rest.
    pub(crate) fn accounted(&self) -> bool {
        if self.image {
            return true;
        }
        self.mapped && super::psapi::mapped_file(self.start)
    }
}

/// Walks the executable regions of this process, in address order.
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
        let mut info = MemoryBasicInformation::default();

        // SAFETY: `info` is a live local with the layout that winnt.h states,
        // and `length` is its own size, so the operating system writes inside
        // it. The address is a value that the walk owns, and the call reads
        // no memory at it.
        let written = unsafe {
            VirtualQuery(
                address as *const c_void,
                &raw mut info,
                size_of::<MemoryBasicInformation>(),
            )
        };

        if written == 0 {
            // The walk ends here. An address above the highest one that the
            // process can reach fails with ERROR_INVALID_PARAMETER, and that
            // is the ordinary end of a complete walk.
            break;
        }

        let size = info.region_size as u64;
        if size == 0 {
            break;
        }

        // A reserved or a free region leaves `protect` and `kind` undefined,
        // so the walk reads neither until the state says the pages are real.
        if info.state == MEM_COMMIT && info.protect & EXECUTE != 0 {
            found.push(Region {
                start: address,
                end: address.saturating_add(size),
                writable: info.protect & EXECUTE_WRITE != 0,
                image: info.kind == MEM_IMAGE,
                mapped: info.kind == MEM_MAPPED,
            });
        }

        let Some(next) = address.checked_add(size) else {
            break;
        };
        address = next;
    }

    if found.is_empty() {
        return Err("the walk reported no executable region for this process");
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::executable;

    #[test]
    fn the_walk_finds_the_executable_code_of_this_process() {
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
    fn the_image_of_this_process_accounts_for_some_of_its_code() {
        // The loader maps this test binary and every module it needs as an
        // image, so a walk that accounted for nothing would read every clean
        // process as injected.
        let regions = executable().unwrap_or_default();
        assert!(regions.iter().any(|region| region.image));
    }

    #[test]
    fn two_walks_of_an_unchanged_process_agree() {
        // The property the detector depends on. A walk that returned a moving
        // answer would report a finding on every cycle. A test runner is not
        // quiet, so the bound takes up to eight pairs and needs one to agree.
        // A walk that really moved would never produce an agreeing pair.
        const ATTEMPTS: usize = 8;

        let agreed = (0..ATTEMPTS)
            .any(|_| executable().unwrap_or_default() == executable().unwrap_or_default());
        assert!(agreed, "no pair of walks agreed, so the walk itself moves");
    }
}
