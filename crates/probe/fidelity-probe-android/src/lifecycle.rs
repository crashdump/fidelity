//! The lifecycle capability on Android.
//!
//! Android is the one system where the worker thread has to join something
//! before it can work: every Java interface needs the thread to belong to the
//! virtual machine. The attachment is a daemon attachment, so it never stops
//! the application from ending.
//!
//! One part of this capability is still absent. A mobile system suspends an
//! application and resumes it later, and `docs/plan/03-runtime-and-api.md`
//! makes a full scan the worker's first work item after a resume. That needs an
//! application lifecycle callback, which the Java side owns.

use fidelity_core::{Lifecycle, WorkerSetup};
use fidelity_types::BoundedText;

use crate::AndroidEnvironment;
use crate::sys::jvm::{self, Attached};

/// What the evidence says when the call attached this thread.
const ATTACHED: &str = "the worker thread joined the virtual machine as a daemon";

/// What the evidence says when the thread already belonged to the machine.
const ALREADY: &str = "the worker thread already belonged to the virtual machine";

/// What the evidence says when the host supplied no handle.
const NO_HANDLE: &str = "this process runs no virtual machine, so no Java interface answers";

impl Lifecycle for AndroidEnvironment {
    fn prepare_worker(&self) -> WorkerSetup {
        // A host that supplied a handle wins, because it knows its own
        // machine. A host that supplied none is the common case, so the probe
        // asks the runtime rather than reporting a gap that it can close
        // itself.
        let address = match self.java_vm() {
            0 => jvm::running().unwrap_or(0),
            given => given,
        };
        if address == 0 {
            return WorkerSetup::Failed {
                detail: BoundedText::new(NO_HANDLE),
            };
        }
        match jvm::attach_as_daemon(address) {
            Attached::AsDaemon => WorkerSetup::Prepared {
                detail: BoundedText::new(ATTACHED),
            },
            Attached::Already => WorkerSetup::Prepared {
                detail: BoundedText::new(ALREADY),
            },
            Attached::Failed(detail) => WorkerSetup::Failed {
                detail: BoundedText::new(detail),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Lifecycle, WorkerSetup};

    use super::AndroidEnvironment;

    #[test]
    fn an_environment_with_no_virtual_machine_reports_that_gap() {
        // The control that needs no JVM. A shell test binary has no virtual
        // machine, so this is what a plain `cargo test` can prove. The
        // instrumented harness proves the attachment itself.
        assert!(matches!(
            AndroidEnvironment::new().prepare_worker(),
            WorkerSetup::Failed { .. }
        ));
    }
}
