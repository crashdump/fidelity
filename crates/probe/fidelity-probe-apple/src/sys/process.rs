//! The BSD process-information boundary.
//!
//! The module reads the kernel's own record of this process through `sysctl`,
//! which Apple's QA1361 names as the way to ask whether a tracer holds the
//! process. The kernel maintains the flag, so a debugger cannot clear it
//! without code that runs inside this process.

use std::ffi::c_void;

/// The kernel namespace of the management interface.
const CTL_KERN: i32 = 1;

/// The process-entry selector.
const KERN_PROC: i32 = 14;

/// Select one process by its identifier.
const KERN_PROC_PID: i32 = 1;

/// A debugger traces the process.
///
/// The value comes from `sys/proc.h` of the macOS SDK, checked on 2026-08-09.
const P_TRACED: i32 = 0x0000_0800;

/// The head of `struct extern_proc`, up to the flags.
///
/// `struct kinfo_proc` starts with `struct extern_proc`, so the offset of
/// `p_flag` inside this type is its offset inside the whole record. The type
/// mirrors the header rather than a measured number, so the compiler computes
/// the offset for each architecture.
///
/// Measured on macOS 26 and ARM64 on 2026-08-09: `kinfo_proc` is 648 bytes and
/// `p_flag` sits at offset 32.
#[repr(C)]
struct ExternProcHead {
    /// A union of two list pointers or a `timeval`, which are the same size.
    _union: [*mut c_void; 2],
    /// `p_vmspace`, the address space.
    _vmspace: *mut c_void,
    /// `p_sigacts`, the signal actions.
    _sigacts: *mut c_void,
    /// `p_flag`, which holds `P_TRACED`.
    flag: i32,
}

/// Where the process flags sit inside the record that the kernel returns.
const FLAG_OFFSET: usize = core::mem::offset_of!(ExternProcHead, flag);

/// How many bytes the flags take.
const FLAG_BYTES: usize = size_of::<i32>();

unsafe extern "C" {
    fn sysctl(
        name: *mut i32,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> i32;
    fn getpid() -> i32;
}

/// What the kernel reports about a tracer on this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The kernel reports no tracer.
    Absent,
    /// The kernel reports a tracer.
    Present,
    /// The call itself failed, so the state is unknown.
    ///
    /// Fidelity never converts a failed call into a clean result, so the
    /// caller turns this into a detector-health finding.
    Failed(&'static str),
}

/// Asks the kernel whether a tracer holds this process.
pub(crate) fn traced() -> Verdict {
    // SAFETY: `getpid` takes no argument and reads no memory. It cannot fail.
    let pid = unsafe { getpid() };
    let mut name = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];

    // The kernel reports the size it wants first. It reports more than one
    // record's worth, because the process list can grow between the two calls,
    // so the buffer below is larger than one record. That is the documented
    // shape of the interface, and an over-sized buffer is safe: the second
    // call writes one record and reports how many bytes it wrote.
    let mut wanted: usize = 0;
    // SAFETY: `name` holds 4 elements, and the length argument says so. A null
    // `oldp` with a valid `oldlenp` asks for the size, which the interface
    // documents. `newp` is null with a zero length, so the call writes no
    // kernel state.
    let probed = unsafe {
        sysctl(
            name.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &raw mut wanted,
            std::ptr::null_mut(),
            0,
        )
    };
    if probed != 0 || wanted < FLAG_OFFSET + FLAG_BYTES {
        return Verdict::Failed("the kernel reported no size for its process record");
    }

    let mut buffer = vec![0_u8; wanted];
    let mut length = wanted;
    // SAFETY: `buffer` holds `wanted` bytes and `length` says so, so the call
    // writes inside the allocation. `name` holds 4 elements, and the length
    // argument says so. `newp` is null with a zero length, so the call writes
    // no kernel state.
    let read = unsafe {
        sysctl(
            name.as_mut_ptr(),
            4,
            buffer.as_mut_ptr().cast::<c_void>(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 || length < FLAG_OFFSET + FLAG_BYTES {
        return Verdict::Failed("the kernel returned no process record");
    }

    // The record is a byte buffer, so read the flags without a reference to a
    // partly initialized struct. `length` covers these bytes, which the check
    // above proved.
    let Some(bytes) = buffer.get(FLAG_OFFSET..FLAG_OFFSET + FLAG_BYTES) else {
        return Verdict::Failed("the process record ended before its flags");
    };
    let Ok(bytes) = <[u8; FLAG_BYTES]>::try_from(bytes) else {
        return Verdict::Failed("the process flags were the wrong size");
    };

    if i32::from_ne_bytes(bytes) & P_TRACED == 0 {
        Verdict::Absent
    } else {
        Verdict::Present
    }
}

#[cfg(test)]
mod tests {
    use super::{FLAG_OFFSET, Verdict, traced};

    #[test]
    fn the_flags_sit_where_the_header_puts_them() {
        // Measured against the macOS SDK on 2026-08-09. A change here means
        // the header changed, and the reader needs a fresh measurement.
        assert_eq!(FLAG_OFFSET, 32);
    }

    #[test]
    fn the_kernel_answers_the_question() {
        // The test runner holds no debugger, so this is the clean control. A
        // failure means the call itself broke, which is the case that must
        // never read as clean.
        assert_eq!(traced(), Verdict::Absent);
    }
}
