//! The import-table boundary.
//!
//! `GetModuleHandleW(NULL)` returns the base of the main module.
//! `K32GetModuleInformation` returns its complete mapped size. The pure PE
//! reader validates every import-table offset inside that slice.
//!
//! Windows resolves the static import table before the entry point runs. A
//! later value change therefore identifies a redirected call.

use core::ffi::c_void;

use fidelity_core::fact::MAX_TARGETS;
use fidelity_formats::pe;

const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;

/// The layout that `K32GetModuleInformation` writes.
#[repr(C)]
struct ModuleInformation {
    base: *mut c_void,
    image_size: u32,
    entry_point: *mut c_void,
}

unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn K32GetModuleInformation(
        process: *mut c_void,
        module: *mut c_void,
        information: *mut ModuleInformation,
        size: u32,
    ) -> i32;
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

/// Reads the checked dispatch targets of the main module.
///
/// Returns `None` when the module names no valid import table.
pub(crate) fn read_targets() -> Option<RawTargets> {
    // SAFETY: a null name selects the module that started this process.
    let module = unsafe { GetModuleHandleW(core::ptr::null()) };
    if module.is_null() {
        return None;
    }

    let mut information = ModuleInformation {
        base: core::ptr::null_mut(),
        image_size: 0,
        entry_point: core::ptr::null_mut(),
    };
    let size = u32::try_from(core::mem::size_of::<ModuleInformation>()).ok()?;

    // SAFETY: `information` is a live output value of `size` bytes. The
    // process pseudo-handle and the module handle both refer to this process.
    let reported =
        unsafe { K32GetModuleInformation(GetCurrentProcess(), module, &raw mut information, size) };
    if reported == 0 || information.base != module || information.image_size == 0 {
        return None;
    }

    let image_size = usize::try_from(information.image_size).ok()?;
    let image = super::memory::copy_readable_allocation(
        information.base as usize,
        image_size,
        MAX_IMAGE_BYTES,
    )?;
    let base_address = information.base as usize as u64;
    let targets = pe::mapped_import_slots(&image, base_address, MAX_TARGETS)?
        .into_iter()
        .map(|(slot, value)| RawTarget { slot, value })
        .collect();

    Some(RawTargets {
        targets,
        bound: true,
    })
}

#[cfg(test)]
mod tests {
    use super::read_targets;

    #[test]
    fn the_running_image_holds_checked_import_targets() {
        let Some(targets) = read_targets() else {
            panic!("the Windows test image must hold an import table");
        };
        assert!(!targets.targets.is_empty());
    }
}
