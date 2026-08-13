//! The running-image boundary.
//!
//! Both identity tiers name the same file, and this module is where that name
//! comes from. `GetModuleFileNameW` with no module answers for the executable
//! that started the process, which is the image whose signature answers for
//! this application.

use core::ffi::c_void;

/// How many UTF-16 code units the path buffer holds.
///
/// A Windows path reaches 32767 code units where a caller opts in, and this
/// buffer holds that, because a truncated path names another file or no file.
const MAX_PATH_UNITS: u32 = 32768;

unsafe extern "system" {
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
}

/// The path of the running image, as a null-terminated wide string.
///
/// # Errors
///
/// Returns the reason the read failed. A caller passes the result straight to
/// another Win32 call, so the terminator stays on the end.
pub(crate) fn path() -> Result<Vec<u16>, &'static str> {
    let mut buffer = vec![0_u16; MAX_PATH_UNITS as usize];

    // SAFETY: `buffer` is a live allocation of `MAX_PATH_UNITS` code units,
    // and `size` states that length, so the call writes inside it. A null
    // module names the executable of this process, which always exists.
    let written =
        unsafe { GetModuleFileNameW(core::ptr::null_mut(), buffer.as_mut_ptr(), MAX_PATH_UNITS) };

    if written == 0 {
        return Err("the operating system named no path for the running image");
    }
    if written >= MAX_PATH_UNITS {
        // The call truncates rather than failing, so a full buffer means the
        // name is longer than this one. A truncated path names another file.
        return Err("the path of the running image did not fit");
    }

    // Keep the terminator, and drop the rest of the buffer.
    buffer.truncate(written as usize + 1);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::path;

    #[test]
    fn the_running_image_names_a_path() {
        let Ok(found) = path() else {
            panic!("the running image must name a path");
        };
        assert!(found.len() > 1);
    }

    #[test]
    fn the_path_ends_with_one_terminator() {
        // Every caller passes this to a Win32 call that reads until the zero,
        // so a missing terminator would read past the allocation.
        let Ok(found) = path() else {
            panic!("the running image must name a path");
        };
        assert_eq!(found.last(), Some(&0));
        assert!(!found[..found.len() - 1].contains(&0));
    }
}
