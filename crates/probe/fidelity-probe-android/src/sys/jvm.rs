//! The Java virtual machine boundary.
//!
//! The worker thread has to belong to the JVM before any Java interface
//! answers, and Android is the only system that needs it. `docs/plan/
//! 06-delivery.md` states the rules that shape this module: the probe takes the
//! handle from the host and defines no `JNI_OnLoad`, because one shared library
//! holds one such function and the host owns it. The worker attaches once as a
//! daemon and never detaches, because the runtime never stops.
//!
//! The workspace holds no external dependency, so this module writes the
//! invocation interface by hand rather than taking the `jni` crate. The layout
//! is the C structure that `jni.h` declares, and it has been stable since
//! JNI 1.2.
//!
//! A daemon attachment is what lets the process exit. A thread attached with
//! `AttachCurrentThread` keeps the virtual machine alive, so a worker that
//! never detaches would stop the application from ending.

use core::ffi::c_void;

/// The JNI version that every supported Android release answers.
const JNI_VERSION_1_6: i32 = 0x0001_0006;

/// The call succeeded.
const JNI_OK: i32 = 0;

/// The calling thread does not belong to the virtual machine yet.
const JNI_EDETACHED: i32 = -2;

/// The invocation interface, as `jni.h` declares it.
///
/// Only the entries this module calls are named. The three reserved slots and
/// the field order come from the header, and a wrong order would call the wrong
/// function, so the offsets matter as much as the signatures.
#[repr(C)]
struct InvokeInterface {
    reserved0: *mut c_void,
    reserved1: *mut c_void,
    reserved2: *mut c_void,
    destroy: *mut c_void,
    attach: *mut c_void,
    detach: *mut c_void,
    get_env: unsafe extern "system" fn(*mut JavaVm, *mut *mut c_void, i32) -> i32,
    attach_daemon: unsafe extern "system" fn(*mut JavaVm, *mut *mut c_void, *mut c_void) -> i32,
}

/// The virtual machine, which is a pointer to its interface table.
#[repr(C)]
pub(crate) struct JavaVm {
    functions: *const InvokeInterface,
}

// The invocation interface of the runtime that already runs this process.
// `jni.h` in the NDK declares it, and `libnativehelper.so` exports it, so it is
// a documented interface rather than a private one.
#[link(name = "nativehelper")]
unsafe extern "system" {
    fn JNI_GetCreatedJavaVMs(machines: *mut *mut JavaVm, capacity: i32, found: *mut i32) -> i32;
}

/// Finds the virtual machine that this process already runs.
///
/// An application process holds exactly one, so the call asks for one. It lets
/// the probe answer without the host passing anything, and a host that passes a
/// handle still wins, because a host knows its own machine and this call only
/// reports what the runtime created.
pub(crate) fn running() -> Option<usize> {
    let mut machine: *mut JavaVm = core::ptr::null_mut();
    let mut found: i32 = 0;
    // SAFETY: the call writes at most one pointer into `machine`, which the
    // capacity argument states, and one count into `found`. Both refer to live
    // locals of this call.
    let result = unsafe { JNI_GetCreatedJavaVMs(&raw mut machine, 1, &raw mut found) };
    if result != JNI_OK || found < 1 || machine.is_null() {
        return None;
    }
    Some(machine as usize)
}

/// What the attach attempt reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attached {
    /// The thread already belonged to the virtual machine.
    Already,
    /// The call attached this thread as a daemon.
    AsDaemon,
    /// The call failed, and the text names the reason.
    Failed(&'static str),
}

/// Attaches the calling thread to the virtual machine, as a daemon.
///
/// `address` is the value that the host supplied, and it must be the pointer
/// that JNI handed the host. The caller keeps that contract: this module cannot
/// check it, because no interface reports whether an address is a live virtual
/// machine.
///
/// A thread that already belongs to the machine reports [`Attached::Already`]
/// and attaches nothing, so a repeated call is safe.
pub(crate) fn attach_as_daemon(address: usize) -> Attached {
    if address == 0 {
        return Attached::Failed("the host supplied no virtual machine");
    }
    let vm = address as *mut JavaVm;

    // SAFETY: the host supplied the address of its virtual machine, and
    // `start()` documents that requirement. A `JavaVm` is a pointer to a
    // function table that outlives the process, and JNI states that the
    // structure is safe to use from any thread.
    let functions = unsafe { (*vm).functions };
    if functions.is_null() {
        return Attached::Failed("the virtual machine exposed no interface table");
    }

    let mut env: *mut c_void = core::ptr::null_mut();
    // SAFETY: `functions` is the table that the machine above exposes, and both
    // pointers refer to live locals of this call. `GetEnv` writes the
    // environment of the calling thread, or reports that the thread is absent.
    let present = unsafe { ((*functions).get_env)(vm, &raw mut env, JNI_VERSION_1_6) };
    if present == JNI_OK {
        return Attached::Already;
    }
    if present != JNI_EDETACHED {
        return Attached::Failed("the virtual machine refused the requested JNI version");
    }

    // SAFETY: the same table and the same live locals. A null third argument
    // asks for the default thread group and no name, which the interface
    // documents.
    let result = unsafe { ((*functions).attach_daemon)(vm, &raw mut env, core::ptr::null_mut()) };
    if result == JNI_OK {
        Attached::AsDaemon
    } else {
        Attached::Failed("the virtual machine refused the attachment")
    }
}

#[cfg(test)]
mod tests {
    use super::{Attached, attach_as_daemon};

    #[test]
    fn an_absent_virtual_machine_reports_a_failure() {
        // The control that a device is not needed for. A host that supplies
        // nothing must reach a stated failure, and never a dereference.
        assert!(matches!(attach_as_daemon(0), Attached::Failed(_)));
    }
}
