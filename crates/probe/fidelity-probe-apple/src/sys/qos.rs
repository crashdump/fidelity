//! The Apple quality-of-service boundary.
//!
//! A thread that Fidelity creates competes with the host for the processor
//! unless it says otherwise. Apple schedules by quality of service, so the
//! worker states its own class once, on its own thread.
//!
//! The class is `QOS_CLASS_UTILITY` and not `QOS_CLASS_BACKGROUND`, and a
//! measurement decided that rather than taste. Both keep the worker away from
//! the interface. Background also throttles, and a detector pays for the
//! throttling directly, because a scan that the scheduler defers extends the
//! time a host stays exposed.
//!
//! Measured on macOS 26 and ARM64 on 2026-08-09, with every core busy and a
//! thread that wakes every 5 s:
//!
//! | Class | Mean drift | Worst drift |
//! |---|---|---|
//! | `QOS_CLASS_UTILITY` | 0.007 s | 0.014 s |
//! | `QOS_CLASS_BACKGROUND` | 0.973 s | 2.102 s |
//!
//! Background therefore adds up to 2.1 s to a 5 s cycle, which is a large share
//! of the exposure window that `docs/plan/05-verification.md` asks a release to
//! record. Utility costs nothing measurable. The worker spends about 92 us for
//! each cycle on macOS, so it is not the thread that drains a battery, and the
//! trade favors detection.
//!
//! The values come from `sys/qos.h` of the macOS SDK, checked on 2026-08-09.

/// Long-running work that the user knows about, without an interface.
const QOS_CLASS_UTILITY: u32 = 0x11;

/// The call succeeded.
const OK: i32 = 0;

unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
}

// The read-back interface, which only the test below needs. A caller that sets
// the class never reads it, so shipping the binding would leave an unused
// foreign symbol in the library.
#[cfg(test)]
unsafe extern "C" {
    fn pthread_get_qos_class_np(
        thread: *mut core::ffi::c_void,
        qos_class: *mut u32,
        relative_priority: *mut i32,
    ) -> i32;
    fn pthread_self() -> *mut core::ffi::c_void;
}

/// Gives the calling thread the worker's quality of service.
///
/// # Errors
///
/// Returns the reason the call failed. A caller keeps running, because a
/// scheduling preference is not worth a worker.
pub(crate) fn take_worker_class() -> Result<(), &'static str> {
    // SAFETY: the call takes two values and no pointer, and it changes the
    // calling thread only. A relative priority of zero is the documented
    // default inside the class.
    let result = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) };
    if result == OK {
        Ok(())
    } else {
        Err("the thread kept its default quality of service")
    }
}

/// Reads the quality of service of the calling thread.
///
/// The test below uses this to prove that the call above took effect. A caller
/// that only sets the class never needs it.
#[cfg(test)]
fn current_class() -> Option<u32> {
    let mut class: u32 = 0;
    let mut relative: i32 = 0;
    // SAFETY: both pointers refer to live locals of this call, and each one has
    // the type the interface writes. `pthread_self` always returns this thread.
    let result =
        unsafe { pthread_get_qos_class_np(pthread_self(), &raw mut class, &raw mut relative) };
    (result == OK).then_some(class)
}

/// The class that a prepared worker thread holds.
#[cfg(test)]
const WORKER_CLASS: u32 = QOS_CLASS_UTILITY;

#[cfg(test)]
mod tests {
    use super::{WORKER_CLASS, current_class, take_worker_class};

    #[test]
    fn the_thread_reports_the_class_that_it_took() {
        // The clean control for the boundary. A call that returned success
        // while the thread kept its old class would leave the worker competing
        // with the host, and nothing else would show it.
        std::thread::spawn(|| {
            assert!(take_worker_class().is_ok());
            assert_eq!(current_class(), Some(WORKER_CLASS));
        })
        .join()
        .unwrap_or_else(|_| panic!("the test thread must finish"));
    }

    #[test]
    fn an_untouched_thread_does_not_hold_the_worker_class() {
        // The other direction. Without this, the test above would pass on a
        // platform where every thread already held the class, and it would
        // prove nothing.
        let observed = std::thread::spawn(current_class)
            .join()
            .unwrap_or_else(|_| panic!("the test thread must finish"));
        assert_ne!(observed, Some(WORKER_CLASS));
    }
}
