use std::sync::{Mutex, PoisonError};

use fidelity_types::{Action, Finding};

/// How many reports this holds before it drops one.
///
/// A host reports what it observed, and a host in a loop must not grow the
/// memory of the process. [State and budgets](../../../docs/plan/07-state-and-budgets.md)
/// states the rule that this keeps: the cost grows with nothing that an
/// attacker chooses. The queue drains on every worker cycle, so it holds one
/// cycle of reports and never a history.
const MOST_REPORTS: usize = 16;

/// The actions that a host report qualified, waiting for the worker.
///
/// A host reports an observation on its own thread, and the caller records it
/// at once, so a `Deny` latches before the call returns and
/// `ensure_allowed()` denies immediately. `Callback` and `Crash` run host code,
/// and only the worker runs host code, so those wait here for one cycle. The
/// initial scan takes the same route: `start()` records it and the worker
/// applies it.
#[derive(Debug, Default)]
pub struct Pending {
    reports: Mutex<Vec<(Finding, Action)>>,
}

impl Pending {
    /// Creates an empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reports: Mutex::new(Vec::new()),
        }
    }

    /// Adds the actions that one report qualified.
    ///
    /// A queue that is already full drops the new report, and it keeps what it
    /// holds. Keeping the older entries means the first report of a burst
    /// still reaches the host, and that is the one that describes the change.
    pub fn add(&self, qualified: Vec<(Finding, Action)>) {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        for entry in qualified {
            if reports.len() >= MOST_REPORTS {
                return;
            }
            reports.push(entry);
        }
    }

    /// Takes everything that waits, and leaves the queue empty.
    #[must_use]
    pub fn take(&self) -> Vec<(Finding, Action)> {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        core::mem::take(&mut reports)
    }
}

#[cfg(test)]
mod tests {
    use fidelity_types::{
        Action, BoundedText, Category, Detector, Evidence, Finding, SignalStrength,
    };

    use super::{MOST_REPORTS, Pending};

    const PROBE: Detector = Detector::new(1, "test.probe", Category::UiAbuse);

    fn report() -> (Finding, Action) {
        (
            Finding::new(
                PROBE,
                SignalStrength::Medium,
                Evidence::InterfaceObserved {
                    detail: BoundedText::new("the host reported one"),
                },
                0,
            ),
            Action::Callback,
        )
    }

    #[test]
    fn a_report_waits_until_something_takes_it() {
        let pending = Pending::new();
        pending.add(vec![report()]);
        assert_eq!(pending.take().len(), 1);
    }

    #[test]
    fn a_take_leaves_the_queue_empty() {
        let pending = Pending::new();
        pending.add(vec![report()]);
        drop(pending.take());
        assert!(pending.take().is_empty());
    }

    #[test]
    fn an_empty_queue_takes_nothing() {
        assert!(Pending::new().take().is_empty());
    }

    #[test]
    fn a_host_that_reports_without_stopping_never_grows_the_queue() {
        // The rule that keeps the cost bounded. A host in a loop must not grow
        // the memory of the process it protects.
        let pending = Pending::new();
        for _ in 0..(MOST_REPORTS * 8) {
            pending.add(vec![report()]);
        }
        assert_eq!(pending.take().len(), MOST_REPORTS);
    }

    #[test]
    fn a_full_queue_keeps_what_it_already_holds() {
        // The first report of a burst describes the change, and a later one
        // repeats it, so the queue drops the later one.
        let pending = Pending::new();
        pending.add(vec![report(); MOST_REPORTS + 4]);
        assert_eq!(pending.take().len(), MOST_REPORTS);
    }
}
