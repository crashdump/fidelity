//! The Win32 module catalog boundary.

use core::ffi::c_void;

/// The module bound. A normal process holds much less than this value.
const MAX_MODULES: usize = 4096;

unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn K32EnumProcessModules(
        process: *mut c_void,
        modules: *mut *mut c_void,
        bytes: u32,
        needed: *mut u32,
    ) -> i32;
}

/// Reads the base address of each module that the loader lists.
pub(crate) fn module_bases() -> Result<Vec<u64>, &'static str> {
    let mut modules = vec![core::ptr::null_mut(); MAX_MODULES];
    let bytes = u32::try_from(modules.len().saturating_mul(size_of::<*mut c_void>()))
        .map_err(|_| "the module-catalog buffer size is invalid")?;
    let mut needed = 0_u32;
    // SAFETY: the buffer holds `bytes` writable bytes, and `needed` is live.
    let ok = unsafe {
        K32EnumProcessModules(
            GetCurrentProcess(),
            modules.as_mut_ptr(),
            bytes,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err("the module-catalog read failed");
    }
    if needed > bytes {
        return Err("the module catalog reached its bound");
    }
    let count = usize::try_from(needed)
        .ok()
        .and_then(|value| value.checked_div(size_of::<*mut c_void>()))
        .ok_or("the module-catalog size is invalid")?;
    modules.truncate(count);
    if modules.is_empty() || modules.iter().any(|module| module.is_null()) {
        return Err("the module catalog reported an invalid base address");
    }
    Ok(modules.into_iter().map(|module| module as u64).collect())
}
