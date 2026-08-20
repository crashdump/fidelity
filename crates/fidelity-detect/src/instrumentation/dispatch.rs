use fidelity_core::{Dispatch, DispatchTargets, Observation, Target};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// A call target of the image of the host points somewhere else than at start.
pub const DISPATCH_TARGETS: Detector = Detector::new(
    9,
    "instrumentation.dispatch_targets",
    Category::Instrumentation,
);

/// The strength of a call target that moved after start.
///
/// `Medium`. The evidence is direct, because a fully bound table does not
/// rewrite its own entries and the target held another value at start.
/// Measured on Linux and ARM64: a redirected `memcpy` slot leaves the runtime
/// baseline clean and turns up here, so this detector catches a hook that maps
/// no new executable region.
///
/// It stays below `High` for the reason the signal model states: an attacker
/// inside the process rewrites the table and the comparison logic together, so
/// the signal has a meaningful user-mode bypass. The detector raises the cost
/// of a hook and does not close it.
const REDIRECTED_STRENGTH: SignalStrength = SignalStrength::Medium;

/// The reason a snapshot of a table that is not fully bound states.
///
/// A table that the loader binds on the first call rewrites its own entries
/// later, so a change there is ordinary and the comparison cannot run.
const NOT_BOUND: &str =
    "the image of the host does not bind its dispatch table fully, so a change there is ordinary";

/// The reason an absent start snapshot states.
const NO_SNAPSHOT: &str = "this build captured no dispatch snapshot at start";

/// The reason a truncated snapshot states.
const TRUNCATED: &str = "the image of the host holds more dispatch targets than a snapshot keeps";

/// Interprets whether a call target of the image of the host moved after start.
///
/// The start snapshot is the table that `start()` captured, before the host
/// ran any of its own work. A fully bound table holds its final values from
/// before the process ran, so a later change arrived from outside.
pub(crate) fn dispatch_targets(
    environment: &(impl Dispatch + ?Sized),
    start: Option<&DispatchTargets>,
    now_unix_ms: u64,
) -> Outcome {
    let Some(start) = start else {
        return Outcome::Unsupported {
            reason: NO_SNAPSHOT,
        };
    };

    // A table that the loader did not bind fully rewrites its own entries on
    // the first call, so the comparison cannot separate that from a hook.
    if !start.is_bound() {
        return Outcome::Unsupported { reason: NOT_BOUND };
    }
    if start.is_truncated() {
        return Outcome::Unsupported { reason: TRUNCATED };
    }

    match environment.dispatch_targets() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(current) => {
            if current.is_truncated() {
                return Outcome::Unsupported { reason: TRUNCATED };
            }
            let redirected = current.redirected_since(start);
            if redirected.is_empty() {
                return Outcome::Clean;
            }
            let first = redirected.first().map_or(0, Target::slot);
            Outcome::Finding(Finding::new(
                DISPATCH_TARGETS,
                REDIRECTED_STRENGTH,
                Evidence::DispatchRedirected {
                    detail: BoundedText::new(format!(
                        "dispatch targets that moved after start: {}, first at {first:#x}",
                        redirected.len()
                    )),
                },
                now_unix_ms,
            ))
        }
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        DISPATCH_TARGETS,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{DispatchTargets, Observation, Target};
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{Evidence, Outcome, SignalStrength};

    use super::{DISPATCH_TARGETS, dispatch_targets};

    const NOW: u64 = 1_700_000_000_000;

    fn bound(pairs: &[(u64, u64)]) -> DispatchTargets {
        DispatchTargets::new(
            pairs
                .iter()
                .map(|&(slot, value)| Target::new(slot, value))
                .collect(),
            true,
        )
    }

    #[test]
    fn an_unchanged_table_is_clean() {
        let start = bound(&[(0x1000, 0xa000), (0x1008, 0xb000)]);
        let environment =
            FakeEnvironment::new().with_dispatch_targets(Observation::Fact(start.clone()));
        assert_eq!(
            dispatch_targets(&environment, Some(&start), NOW),
            Outcome::Clean
        );
    }

    #[test]
    fn a_redirected_target_reports_a_medium_finding() {
        let start = bound(&[(0x1000, 0xa000), (0x1008, 0xb000)]);
        let now = bound(&[(0x1000, 0xa000), (0x1008, 0xc000)]);
        let environment = FakeEnvironment::new().with_dispatch_targets(Observation::Fact(now));
        let Outcome::Finding(finding) = dispatch_targets(&environment, Some(&start), NOW) else {
            panic!("a redirected target must report a finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
        assert!(matches!(
            finding.evidence(),
            Evidence::DispatchRedirected { .. }
        ));
    }

    #[test]
    fn a_table_that_is_not_fully_bound_reports_unsupported() {
        // A lazily bound table rewrites its own entries on the first call, so
        // the comparison would report a process that only made a call.
        let start = DispatchTargets::new(vec![Target::new(0x1000, 0xa000)], false);
        let environment =
            FakeEnvironment::new().with_dispatch_targets(Observation::Fact(start.clone()));
        assert!(matches!(
            dispatch_targets(&environment, Some(&start), NOW),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn an_absent_start_snapshot_reports_unsupported() {
        let environment = FakeEnvironment::new()
            .with_dispatch_targets(Observation::Fact(bound(&[(0x1000, 0xa000)])));
        assert!(matches!(
            dispatch_targets(&environment, None, NOW),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_platform_with_no_dispatch_probe_reports_unsupported() {
        let start = bound(&[(0x1000, 0xa000)]);
        assert!(matches!(
            dispatch_targets(&FakeEnvironment::new(), Some(&start), NOW),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_failed_probe_never_reads_as_clean() {
        let start = bound(&[(0x1000, 0xa000)]);
        let environment = FakeEnvironment::new()
            .with_dispatch_targets(Observation::failed("the loader walk returned nothing"));
        let Outcome::Finding(finding) = dispatch_targets(&environment, Some(&start), NOW) else {
            panic!("a failed probe must report a health finding");
        };
        assert_eq!(finding.detector(), DISPATCH_TARGETS);
        assert!(finding.evidence().is_detector_health());
    }
}
