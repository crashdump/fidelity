//! The lifecycle body that both Apple systems run.
//!
//! Both systems schedule by quality of service, and both set it the same way,
//! so the body is here rather than in one system's module.

use fidelity_core::WorkerSetup;
use fidelity_types::BoundedText;

use crate::sys::qos;

/// What the evidence says when the thread took the worker class.
const TOOK: &str = "the worker thread took a utility quality of service";

/// Gives the calling thread the quality of service that the worker wants.
pub(crate) fn prepare_worker() -> WorkerSetup {
    match qos::take_worker_class() {
        Ok(()) => WorkerSetup::Prepared {
            detail: BoundedText::new(TOOK),
        },
        Err(detail) => WorkerSetup::Failed {
            detail: BoundedText::new(detail),
        },
    }
}
