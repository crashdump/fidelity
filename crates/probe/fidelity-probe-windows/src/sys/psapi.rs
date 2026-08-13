//! The process-status boundary, for the origin of one mapped region.
//!
//! `VirtualQuery` states that a region is a view of a section, and it does not
//! state what backs that section. A file backs one kind, and the page file
//! backs the other. A manual mapper uses the second kind, so the two must stay
//! apart, and this is the documented call that separates them.
//!
//! This is the Windows form of the rule that
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! states for Linux: a region that the kernel named does not count as
//! unaccounted.

use core::ffi::c_void;

/// How many UTF-16 code units the call may write.
///
/// The caller needs no name, only the answer to whether one exists, so the
/// buffer is small on purpose. A name that does not fit truncates and returns
/// this length, which is still a success, and a success is the whole answer.
const BUFFER: u32 = 64;

unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;

    /// The Windows 7 and later name of `GetMappedFileNameW`.
    ///
    /// Microsoft exports the function from Kernel32.dll under this name, and
    /// the Psapi.dll form is a wrapper that calls it. The v1 floor is Windows
    /// 11, so the probe calls the exported name and links no second library.
    /// Checked against the psapi.h reference on 2026-08-13.
    fn K32GetMappedFileNameW(
        process: *mut c_void,
        address: *const c_void,
        filename: *mut u16,
        size: u32,
    ) -> u32;
}

/// Whether a file on disk backs the section at this address.
///
/// Returns `false` when the address belongs to no mapped file, which is what
/// the call reports for a section that the page file backs.
pub(crate) fn mapped_file(address: u64) -> bool {
    let mut name = [0_u16; BUFFER as usize];

    // SAFETY: `name` is a live local of `BUFFER` code units, and the call
    // writes at most that many. The process handle is the pseudo-handle for
    // this process, which is always valid and needs no close. The address is a
    // value that the caller read from a region walk, and the call reads no
    // memory at it.
    let written = unsafe {
        K32GetMappedFileNameW(
            GetCurrentProcess(),
            address as *const c_void,
            name.as_mut_ptr(),
            BUFFER,
        )
    };

    written != 0
}

#[cfg(test)]
mod tests {
    use super::mapped_file;

    #[test]
    fn an_address_that_no_section_holds_names_no_file() {
        // The null page belongs to no mapping at all, so the call must fail
        // rather than name something. A function that answered `true` here
        // would account for every region and report no injection ever.
        assert!(!mapped_file(0));
    }

    #[test]
    fn the_code_of_this_process_names_a_file() {
        // The loader mapped this test binary from disk, so the address of a
        // function inside it belongs to a named file. This proves the call
        // reaches the operating system, which the negative test cannot.
        let here = mapped_file as *const () as usize as u64;
        assert!(mapped_file(here));
    }
}
