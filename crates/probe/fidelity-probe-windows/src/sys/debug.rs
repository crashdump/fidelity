//! The debug boundary.
//!
//! Windows offers two calls, and the probe takes the stronger one.
//! `IsDebuggerPresent` reads the `BeingDebugged` byte of the process
//! environment block, which is memory inside this process, so an attacker who
//! already runs here clears one byte and the answer changes.
//! `CheckRemoteDebuggerPresent` asks the kernel about the debug port of the
//! process, which is the same state that `P_TRACED` reports on Apple and that
//! `TracerPid` reports on Linux.
//!
//! The strength stays `Medium` either way, because one call site still answers
//! for the operating system. See
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md).

use core::ffi::c_void;

unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CheckRemoteDebuggerPresent(process: *mut c_void, present: *mut i32) -> i32;
}

/// Whether the kernel reports a debugger on this process.
///
/// # Errors
///
/// Returns the reason the call failed. A failed call is never a clean result.
pub(crate) fn debugger_present() -> Result<bool, &'static str> {
    let mut present: i32 = 0;

    // SAFETY: `present` is a live local, and the call writes one `BOOL` into
    // it. The process handle is the pseudo-handle for this process, which is
    // always valid and needs no close.
    let ok = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &raw mut present) };

    if ok == 0 {
        return Err("CheckRemoteDebuggerPresent failed on this process");
    }
    Ok(present != 0)
}

#[cfg(test)]
mod tests {
    use super::debugger_present;

    #[test]
    fn the_call_answers_for_this_process() {
        // The boundary control. The value depends on whether a debugger runs
        // the test, so the test states only that the call succeeds.
        assert!(debugger_present().is_ok());
    }
}
