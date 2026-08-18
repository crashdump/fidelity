//! The virtual machine monitor boundary.
//!
//! The kernel keeps one value that states whether a virtual machine monitor
//! runs it, and this module reads that value. The kernel is the one part of
//! the system that sees the boundary, so it is the only part that can answer.
//!
//! This is not the processor flag that
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! excludes. That flag answers whether the processor offers virtualization,
//! and a plain machine reports it. Apple reads the value below in its own
//! content cache, which refuses to run when it reports a guest.

use std::ffi::{c_char, c_void};

/// The name of the value that the kernel answers.
///
/// Do not confuse it with `kern.hv_support`, which states that this machine
/// can host a guest. Ordinary hardware reports 1 there, so a check on that
/// name reports every clean Apple Silicon Mac.
const NAME: &[u8] = b"kern.hv_vmm_present\0";

/// What the kernel does not hold, in the C error numbers of this system.
///
/// A kernel that offers no such value cannot answer, and Fidelity reports that
/// as unsupported rather than as a clean result.
const NO_SUCH_NAME: i32 = 2;

/// What the kernel reports about the machine below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The kernel reports that it runs on the hardware.
    Hardware,

    /// The kernel reports that a virtual machine monitor runs it.
    VirtualMachine,

    /// The kernel holds no such value, so it cannot answer.
    Absent(&'static str),

    /// The call itself failed, so the state is unknown.
    ///
    /// Fidelity never converts a failed call into a clean result, so the
    /// caller turns this into a detector-health finding.
    Failed(&'static str),
}

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> i32;
}

/// Asks the kernel whether a virtual machine monitor runs it.
pub(crate) fn present() -> Verdict {
    let mut value: i32 = 0;
    let mut length = size_of::<i32>();

    // SAFETY: `NAME` ends with a zero byte, so it is a C string. `oldp` points
    // at one `i32` and `length` says so, which is the size the kernel reports
    // for this name. `newp` is null with a zero length, so the call writes no
    // kernel state.
    let read = unsafe {
        sysctlbyname(
            NAME.as_ptr().cast::<c_char>(),
            (&raw mut value).cast::<c_void>(),
            &raw mut length,
            std::ptr::null(),
            0,
        )
    };

    if read != 0 {
        // The C library set the error number, and the standard library reads
        // it. A kernel with no such name is a gap, and anything else is a
        // failure that must never read as clean.
        if std::io::Error::last_os_error().raw_os_error() == Some(NO_SUCH_NAME) {
            return Verdict::Absent("this kernel holds no kern.hv_vmm_present");
        }
        return Verdict::Failed("the kernel did not answer kern.hv_vmm_present");
    }
    if length != size_of::<i32>() {
        return Verdict::Failed("the kernel answered kern.hv_vmm_present with another size");
    }

    if value == 0 {
        Verdict::Hardware
    } else {
        Verdict::VirtualMachine
    }
}

#[cfg(test)]
mod tests {
    use super::{Verdict, present};

    #[test]
    fn the_kernel_answers_the_question() {
        // A failure is what must never happen. Which of the two facts this
        // reports depends on the machine, and `tests/platform/README.md` records
        // both a bare-metal run and a guest run.
        assert!(
            matches!(present(), Verdict::Hardware | Verdict::VirtualMachine),
            "{:?}",
            present()
        );
    }
}
