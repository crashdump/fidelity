//! The iOS machine-name boundary.

use std::ffi::{c_char, c_void};

/// The kernel value that names the machine.
const NAME: &[u8] = b"hw.machine\0";

/// The largest machine name that this boundary accepts.
const LIMIT: usize = 128;

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> i32;
}

/// Reads the product name or the host architecture that iOS reports.
pub(crate) fn name() -> Result<String, &'static str> {
    let mut bytes = [0_u8; LIMIT];
    let mut length = bytes.len();

    // SAFETY: `NAME` ends with a zero byte. `bytes` owns `length` writable
    // bytes. The null new-value pointer makes this a read-only call.
    let result = unsafe {
        sysctlbyname(
            NAME.as_ptr().cast::<c_char>(),
            bytes.as_mut_ptr().cast::<c_void>(),
            &raw mut length,
            std::ptr::null(),
            0,
        )
    };
    if result != 0 {
        return Err("the kernel did not answer hw.machine");
    }
    if length == 0 || length > bytes.len() {
        return Err("the kernel answered hw.machine with an invalid size");
    }

    let text = bytes[..length]
        .strip_suffix(&[0])
        .unwrap_or(&bytes[..length]);
    let Ok(text) = std::str::from_utf8(text) else {
        return Err("the kernel answered hw.machine with invalid text");
    };
    if text.is_empty() {
        return Err("the kernel answered hw.machine with an empty name");
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn the_kernel_answers_with_a_machine_name() {
        let name = name();
        assert!(
            name.as_ref().is_ok_and(|value| !value.is_empty()),
            "{name:?}"
        );
    }
}
