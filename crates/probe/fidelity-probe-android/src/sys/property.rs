//! The system property boundary.
//!
//! Android keeps its build description in a property store that every process
//! can read. `__system_property_get` is the documented interface, and the NDK
//! declares it in `<sys/system_properties.h>`, so this is a stable interface
//! and not an SPI.
//!
//! The store is the right source for this question and a weak source for a
//! stronger one. A root user rewrites it, so what it reports is a statement
//! that the system makes about itself, and never proof.
//! [Detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! sets the strength from that fact.

use core::ffi::{CStr, c_char, c_int};

/// The largest value that the property store holds, which bionic fixes at 92
/// bytes and includes the terminator.
///
/// The interface writes up to this many bytes and states no length in its
/// arguments, so a smaller buffer would be a memory error rather than a
/// truncation.
const VALUE_MAX: usize = 92;

unsafe extern "C" {
    /// Copies the value of one property into `value`.
    ///
    /// Returns the length that it wrote, and zero when the property is absent.
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

/// Reads one system property.
///
/// Returns `None` when the property is absent, when it holds nothing, or when
/// it is not UTF-8. Each one means the same thing to a caller: this system
/// stated nothing here.
pub(crate) fn read(name: &CStr) -> Option<String> {
    let mut value = [0_u8; VALUE_MAX];

    // SAFETY: `name` is a `CStr`, so it is nul-terminated and its pointer is
    // valid for the whole call. The interface writes up to `VALUE_MAX` bytes
    // into `value`, and `value` holds exactly that many. Both pointers are
    // valid for the duration of one call, and the interface keeps neither.
    let written = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr().cast()) };

    let length = usize::try_from(written).ok()?;
    let text = value.get(..length)?;
    if text.is_empty() {
        return None;
    }
    core::str::from_utf8(text).ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::read;

    #[test]
    fn the_store_names_the_android_release() {
        // The clean control for the boundary. Every Android system holds this
        // property, so an empty answer means the read itself failed.
        let Some(release) = read(c"ro.build.version.release") else {
            panic!("every Android system states its release")
        };
        assert!(!release.is_empty());
    }

    #[test]
    fn a_property_that_no_system_holds_reports_none() {
        // The negative control. An absent property must never read as a value,
        // because a detector treats an absent answer and a stated answer
        // differently.
        assert_eq!(read(c"fidelity.property.that.no.system.holds"), None);
    }
}
