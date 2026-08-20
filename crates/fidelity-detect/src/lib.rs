//! The fixed set of built-in detectors.
//!
//! A detector turns the facts that a probe reports into a category, a
//! strength, and typed evidence. Every detector here is safe portable Rust
//! over the [`fidelity_core::Environment`] trait, so the logic for
//! any target compiles and tests on an ordinary runner.
//!
//! Composition is fixed at compile time. Fidelity loads no detector at run
//! time, and it exposes no third-party detector trait.
//!
//! # Layout
//!
//! One module per category, named as `fidelity_types::Category` names it, and
//! one file per detector inside it. `integrity`, `debugging`,
//! `instrumentation`, `device_compromise`, and `virtualization` carry a
//! detector so far. The last one arrives with its platform tests:
//! `ui_abuse`.
//!
//! A detector takes the narrow capability that it reads, not the whole
//! environment, so its signature states what it touches.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.

#![forbid(unsafe_code)]

use fidelity_core::{CodeRegions, DispatchTargets, Environment};
use fidelity_types::{
    BoundedText, Detector, Evidence, ExpectedIdentity, Finding, Outcome, SignalStrength,
};

mod debugging;
mod device_compromise;
mod instrumentation;
mod integrity;
mod ui_abuse;
mod virtualization;

pub use debugging::TRACER_PRESENT;
pub use device_compromise::SYSTEM_BUILD;
pub use instrumentation::{DISPATCH_TARGETS, UNACCOUNTED_CODE};
pub use integrity::{EXPECTED_IDENTITY, PLATFORM_TRUST, RUNTIME_BASELINE};
pub use ui_abuse::{HOST_REPORT, host_report};
pub use virtualization::MACHINE_HOST;

/// What `start()` captured for a detector that compares against a snapshot.
///
/// A snapshot that `start()` reads is one of three things, and the two that
/// are not a snapshot must stay apart. A platform that cannot answer is
/// [`Unsupported`](Captured::Unsupported), and the detector states that gap for
/// the life of the runtime. A read that failed is [`Failed`](Captured::Failed),
/// and the detector reports a `Low` health finding, because a transient failure
/// must never read as a platform that cannot answer. The outcome rule in
/// `docs/plan/04-detectors-and-platforms.md` is why the two do not merge, and
/// an `Option` merged them until 2026-08-20.
#[derive(Debug)]
pub enum Captured<T> {
    /// The read answered, and the snapshot is here.
    Snapshot(T),

    /// The platform answers nothing, so the detector states a gap.
    Unsupported,

    /// The read failed, so the detector reports a `Low` health finding.
    Failed(BoundedText),
}

impl<T> Captured<T> {
    /// Borrows the snapshot, so the detector reads without taking ownership.
    ///
    /// This mirrors `Option::as_ref`, so a caller that held an `Option` keeps
    /// the same shape.
    pub fn as_ref(&self) -> Captured<&T> {
        match self {
            Self::Snapshot(value) => Captured::Snapshot(value),
            Self::Unsupported => Captured::Unsupported,
            Self::Failed(detail) => Captured::Failed(detail.clone()),
        }
    }
}

/// Every detector that this build composes.
///
/// The engine creates one state slot for each entry, and an observation
/// cannot create a slot, so the list is fixed before the first scan.
pub const INVENTORY: &[Detector] = &[
    PLATFORM_TRUST,
    EXPECTED_IDENTITY,
    TRACER_PRESENT,
    UNACCOUNTED_CODE,
    DISPATCH_TARGETS,
    RUNTIME_BASELINE,
    SYSTEM_BUILD,
    MACHINE_HOST,
    HOST_REPORT,
];

/// The built-in detectors, with the configuration they need.
///
/// The set is closed. A host configures a category, not a detector.
#[derive(Debug)]
pub struct Detectors {
    expected: Option<ExpectedIdentity>,
    baseline: Captured<CodeRegions>,
    dispatch: Captured<DispatchTargets>,
}

impl Detectors {
    /// Composes the detectors for one runtime.
    ///
    /// The baseline and the dispatch snapshot are what `start()` captured,
    /// before the host ran any of its own work. Both are immutable for the
    /// life of the runtime, because a snapshot that a later scan could move
    /// would prove nothing.
    #[must_use]
    pub const fn new(
        expected: Option<ExpectedIdentity>,
        baseline: Captured<CodeRegions>,
        dispatch: Captured<DispatchTargets>,
    ) -> Self {
        Self {
            expected,
            baseline,
            dispatch,
        }
    }

    /// Runs the detectors whose probes are bounded and cheap.
    ///
    /// The synchronous initial scan calls this, so every probe here must
    /// finish inside the startup bound. A slow probe belongs in
    /// [`scan_all`](Detectors::scan_all).
    #[must_use]
    pub fn scan_cheap(
        &self,
        environment: &dyn Environment,
        now_unix_ms: u64,
    ) -> Vec<(Detector, Outcome)> {
        vec![
            guarded(PLATFORM_TRUST, now_unix_ms, || {
                integrity::platform_trust(environment, now_unix_ms)
            }),
            guarded(EXPECTED_IDENTITY, now_unix_ms, || {
                integrity::expected_identity(environment, self.expected.as_ref(), now_unix_ms)
            }),
            guarded(TRACER_PRESENT, now_unix_ms, || {
                debugging::tracer_present(environment, now_unix_ms)
            }),
            guarded(UNACCOUNTED_CODE, now_unix_ms, || {
                instrumentation::unaccounted_code(environment, now_unix_ms)
            }),
            guarded(DISPATCH_TARGETS, now_unix_ms, || {
                instrumentation::dispatch_targets(environment, self.dispatch.as_ref(), now_unix_ms)
            }),
            guarded(RUNTIME_BASELINE, now_unix_ms, || {
                integrity::runtime_baseline(environment, self.baseline.as_ref(), now_unix_ms)
            }),
            guarded(SYSTEM_BUILD, now_unix_ms, || {
                device_compromise::system_build(environment, now_unix_ms)
            }),
            guarded(MACHINE_HOST, now_unix_ms, || {
                virtualization::machine_host(environment, now_unix_ms)
            }),
        ]
    }

    /// Runs every detector.
    ///
    /// The worker calls this on its first cycle, and on each later full cycle.
    /// Every detector in this build is cheap, so this runs the same set that
    /// [`scan_cheap`](Detectors::scan_cheap) runs.
    #[must_use]
    pub fn scan_all(
        &self,
        environment: &dyn Environment,
        now_unix_ms: u64,
    ) -> Vec<(Detector, Outcome)> {
        self.scan_cheap(environment, now_unix_ms)
    }
}

/// What a detector reports when it panics.
const PANICKED: &str = "the detector panicked, so this scan reports its health";

/// Runs one detector, and turns a panic into a `Low` health finding.
///
/// [Detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
/// states the rule. A panic is neither a clean result nor an unsupported one,
/// the detector reports its own health, and the worker continues. Without this
/// the unwind leaves the scan, ends the only worker thread, and the runtime
/// then reports nothing at all for the life of the process.
///
/// A repeated panic never disables the detector, because a detector that
/// switches itself off is a target. Every later scan calls it again.
///
/// A host that builds with `panic = "abort"` gets no unwind and no catch. The
/// process stops instead, which is that host's own choice.
fn guarded(
    detector: Detector,
    now_unix_ms: u64,
    scan: impl FnOnce() -> Outcome,
) -> (Detector, Outcome) {
    // The closure reads the environment through a shared reference and writes
    // no state that outlives the call, so a panic leaves nothing half written
    // for a later scan to read. The engine owns every value that survives, and
    // this call touches none of it.
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(scan));
    let outcome = caught.unwrap_or_else(|_| {
        Outcome::Finding(Finding::new(
            detector,
            SignalStrength::Low,
            Evidence::DetectorHealth {
                detail: BoundedText::new(PANICKED),
            },
            now_unix_ms,
        ))
    });
    (detector, outcome)
}

#[cfg(test)]
mod tests {
    use fidelity_core::{
        CodeIdentity, CodeOrigin, CodeRegions, IdentityMatch, MachineHost, Observation,
        PlatformTrust, Region, Signer, TracerState,
    };
    use fidelity_testkit::FakeEnvironment;
    use fidelity_types::{
        BoundedText, Choice, CodeRequirement, Evidence, ExpectedIdentity, IdentityError, Outcome,
        SignalStrength,
    };

    use super::{
        Captured, Detectors, EXPECTED_IDENTITY, HOST_REPORT, INVENTORY, MACHINE_HOST,
        PLATFORM_TRUST, RUNTIME_BASELINE, TRACER_PRESENT, UNACCOUNTED_CODE,
    };

    const NOW: u64 = 1_700_000_000_000;

    /// How many inventory entries no scan reports.
    ///
    /// `HOST_REPORT` is the one. It holds a state slot, because the host
    /// reports into it, and no scan reaches it.
    const HOST_FED: usize = 1;

    /// An environment whose tracer capability panics.
    ///
    /// No fake supplies this, because a fake answers with a value and this one
    /// answers with an unwind. It is the only way to reach the catch.
    struct PanickingTracer;

    impl fidelity_core::Lifecycle for PanickingTracer {}
    impl fidelity_core::Baseline for PanickingTracer {}
    impl fidelity_core::Dispatch for PanickingTracer {}
    impl fidelity_core::Injection for PanickingTracer {}
    impl fidelity_core::Identity for PanickingTracer {}
    impl fidelity_core::Device for PanickingTracer {}
    impl fidelity_core::Emulation for PanickingTracer {}

    impl fidelity_core::Tracer for PanickingTracer {
        fn tracer_state(&self) -> Observation<TracerState> {
            panic!("the probe broke")
        }
    }

    impl fidelity_core::Environment for PanickingTracer {
        fn platform(&self) -> fidelity_types::Platform {
            fidelity_types::Platform::Linux
        }
    }

    #[test]
    fn a_capability_that_panics_reports_health_and_the_scan_still_answers() {
        // The rule is in `04-detectors-and-platforms.md`: a panic is neither a
        // clean result nor an unsupported one, and the worker continues.
        // Without the catch this unwind ends the only worker thread, and the
        // runtime then reports nothing for the life of the process. The test
        // prints the panic that it causes, and that output is expected.
        let outcomes = Detectors::new(None, Captured::Unsupported, Captured::Unsupported)
            .scan_cheap(&PanickingTracer, NOW);

        assert_eq!(
            outcomes.len(),
            INVENTORY.len() - HOST_FED,
            "every detector that a scan reaches still answers"
        );

        let Some((_, outcome)) = outcomes
            .iter()
            .find(|(detector, _)| *detector == TRACER_PRESENT)
        else {
            panic!("the tracer detector must answer")
        };
        let Outcome::Finding(finding) = outcome else {
            panic!("a panic must produce a finding")
        };
        assert_eq!(finding.strength(), SignalStrength::Low);
        assert!(finding.evidence().is_detector_health());
    }

    fn accepted() -> CodeIdentity {
        CodeIdentity::new(
            PlatformTrust::Accepted,
            Some(Signer::new(*b"ABCDE12345", "team ABCDE12345")),
        )
    }

    fn requirement() -> Result<ExpectedIdentity, IdentityError> {
        Ok(
            ExpectedIdentity::new().macos(Choice::Value(CodeRequirement::new(
                "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\"",
            )?)),
        )
    }

    fn outcome_of(
        environment: &FakeEnvironment,
        expected: Option<ExpectedIdentity>,
        detector: fidelity_types::Detector,
    ) -> Outcome {
        Detectors::new(expected, Captured::Unsupported, Captured::Unsupported)
            .scan_cheap(environment, NOW)
            .into_iter()
            .find(|(candidate, _)| *candidate == detector)
            .map_or(Outcome::NotRun, |(_, outcome)| outcome)
    }

    #[test]
    fn the_inventory_holds_every_detector_that_a_scan_reports() {
        // The engine creates one state slot for each inventory entry, and an
        // observation cannot create a slot, so a scan that reported a detector
        // the inventory lacks would report into nothing.
        let reported = Detectors::new(None, Captured::Unsupported, Captured::Unsupported)
            .scan_cheap(&FakeEnvironment::new(), NOW);
        for (detector, _) in &reported {
            assert!(
                INVENTORY.contains(detector),
                "{} reports, and the inventory holds no slot for it",
                detector.name()
            );
        }
        assert_eq!(reported.len(), INVENTORY.len() - HOST_FED);
    }

    #[test]
    fn the_host_fed_detector_holds_a_slot_and_no_scan_reports_it() {
        // The other direction, and it is not the same rule. `HOST_REPORT`
        // takes its input from the host, so it needs a slot and no scan may
        // fill it. A scan that reported it would state something the host
        // never said.
        assert!(INVENTORY.contains(&HOST_REPORT));
        let reported = Detectors::new(None, Captured::Unsupported, Captured::Unsupported)
            .scan_cheap(&FakeEnvironment::new(), NOW);
        assert!(
            !reported
                .iter()
                .any(|(detector, _)| *detector == HOST_REPORT)
        );
    }

    #[test]
    fn an_accepted_image_is_clean() {
        let environment = FakeEnvironment::new().with_code_identity(Observation::Fact(accepted()));
        assert_eq!(
            outcome_of(&environment, None, PLATFORM_TRUST),
            Outcome::Clean
        );
    }

    #[test]
    fn a_rejected_image_reports_a_finding() {
        let environment =
            FakeEnvironment::new().with_code_identity(Observation::Fact(CodeIdentity::new(
                PlatformTrust::Rejected {
                    detail: BoundedText::new("the anchor check failed"),
                },
                None,
            )));
        let outcome = outcome_of(&environment, None, PLATFORM_TRUST);
        let Outcome::Finding(finding) = outcome else {
            unreachable!("a rejected image produces a finding")
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
        assert!(matches!(
            finding.evidence(),
            Evidence::ImageUntrusted { .. }
        ));
    }

    #[test]
    fn a_platform_without_the_check_reports_no_finding() {
        let environment =
            FakeEnvironment::new().with_code_identity(Observation::Fact(CodeIdentity::new(
                PlatformTrust::Unavailable {
                    reason: "the kernel enforces signing and exposes no equivalent API",
                },
                None,
            )));
        assert!(matches!(
            outcome_of(&environment, None, PLATFORM_TRUST),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_failed_probe_never_reads_as_clean() {
        let environment =
            FakeEnvironment::new().with_code_identity(Observation::failed("the call returned -1"));
        let outcome = outcome_of(&environment, None, PLATFORM_TRUST);
        let Outcome::Finding(finding) = outcome else {
            unreachable!("a failed probe produces a health finding")
        };
        assert_eq!(finding.strength(), SignalStrength::Low);
        assert!(finding.evidence().is_detector_health());
    }

    #[test]
    fn an_absent_host_value_reports_unsupported() {
        let environment = FakeEnvironment::new()
            .with_code_identity(Observation::Fact(accepted()))
            .with_identity_match(Observation::Fact(IdentityMatch::Same));
        assert!(matches!(
            outcome_of(&environment, None, EXPECTED_IDENTITY),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_matching_image_is_clean() -> Result<(), IdentityError> {
        let environment =
            FakeEnvironment::new().with_identity_match(Observation::Fact(IdentityMatch::Same));
        let outcome = outcome_of(&environment, Some(requirement()?), EXPECTED_IDENTITY);
        assert_eq!(outcome, Outcome::Clean);
        Ok(())
    }

    #[test]
    fn a_repackaged_image_reports_a_high_finding() -> Result<(), IdentityError> {
        let environment = FakeEnvironment::new().with_identity_match(Observation::Fact(
            IdentityMatch::Different {
                detail: BoundedText::new("the requirement did not match"),
            },
        ));
        let outcome = outcome_of(&environment, Some(requirement()?), EXPECTED_IDENTITY);
        let Outcome::Finding(finding) = outcome else {
            unreachable!("a repackaged image produces a finding")
        };
        assert_eq!(finding.strength(), SignalStrength::High);
        assert!(matches!(
            finding.evidence(),
            Evidence::UnexpectedIdentity { .. }
        ));
        Ok(())
    }

    #[test]
    fn an_accepted_gap_reports_no_finding() {
        // The host stated that this platform runs without the check.
        let environment = FakeEnvironment::new().with_identity_match(Observation::Unsupported {
            reason: "the host accepted no identity check on this platform",
        });
        let expected = ExpectedIdentity::new().macos(Choice::AcceptUnsupported);
        assert!(matches!(
            outcome_of(&environment, Some(expected), EXPECTED_IDENTITY),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_failed_identity_probe_never_reads_as_clean() -> Result<(), IdentityError> {
        let environment = FakeEnvironment::new()
            .with_identity_match(Observation::failed("the requirement did not parse"));
        let outcome = outcome_of(&environment, Some(requirement()?), EXPECTED_IDENTITY);
        let Outcome::Finding(finding) = outcome else {
            unreachable!("a failed probe produces a health finding")
        };
        assert!(finding.evidence().is_detector_health());
        Ok(())
    }

    #[test]
    fn the_two_detectors_stay_independent() -> Result<(), IdentityError> {
        // A clean anchor with a repackaged identity must report exactly one
        // finding, because the tiers answer different questions.
        let environment = FakeEnvironment::new()
            .with_code_identity(Observation::Fact(accepted()))
            .with_identity_match(Observation::Fact(IdentityMatch::Different {
                detail: BoundedText::new("the requirement did not match"),
            }));
        assert_eq!(
            outcome_of(&environment, Some(requirement()?), PLATFORM_TRUST),
            Outcome::Clean
        );
        assert!(matches!(
            outcome_of(&environment, Some(requirement()?), EXPECTED_IDENTITY),
            Outcome::Finding(_)
        ));
        Ok(())
    }
    #[test]
    fn a_process_with_no_tracer_is_clean() {
        let environment =
            FakeEnvironment::new().with_tracer_state(Observation::Fact(TracerState::Absent));
        assert_eq!(
            outcome_of(&environment, None, TRACER_PRESENT),
            Outcome::Clean
        );
    }

    #[test]
    fn a_traced_process_reports_a_medium_finding() {
        let environment =
            FakeEnvironment::new().with_tracer_state(Observation::Fact(TracerState::Present {
                detail: BoundedText::new("the kernel reports P_TRACED on this process"),
            }));
        let Outcome::Finding(finding) = outcome_of(&environment, None, TRACER_PRESENT) else {
            panic!("a traced process must report a finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
    }

    #[test]
    fn a_traced_process_carries_tracer_evidence() {
        let environment =
            FakeEnvironment::new().with_tracer_state(Observation::Fact(TracerState::Present {
                detail: BoundedText::new("the kernel reports P_TRACED on this process"),
            }));
        let Outcome::Finding(finding) = outcome_of(&environment, None, TRACER_PRESENT) else {
            panic!("a traced process must report a finding");
        };
        assert!(matches!(finding.evidence(), Evidence::TracerPresent { .. }));
    }

    #[test]
    fn a_failed_tracer_probe_never_reads_as_clean() {
        // The rule that the security model states: Fidelity never converts a
        // detector error into a clean result.
        let environment = FakeEnvironment::new().with_tracer_state(Observation::Failed {
            detail: BoundedText::new("the kernel returned no process record"),
        });
        let Outcome::Finding(finding) = outcome_of(&environment, None, TRACER_PRESENT) else {
            panic!("a failed probe must report a health finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Low);
    }

    #[test]
    fn a_failed_tracer_probe_reports_detector_health() {
        let environment = FakeEnvironment::new().with_tracer_state(Observation::Failed {
            detail: BoundedText::new("the kernel returned no process record"),
        });
        let Outcome::Finding(finding) = outcome_of(&environment, None, TRACER_PRESENT) else {
            panic!("a failed probe must report a health finding");
        };
        assert!(finding.evidence().is_detector_health());
    }

    #[test]
    fn a_platform_with_no_tracer_probe_reports_unsupported() {
        assert!(matches!(
            outcome_of(&FakeEnvironment::new(), None, TRACER_PRESENT),
            Outcome::Unsupported { .. }
        ));
    }
    #[test]
    fn a_system_on_hardware_is_clean() {
        let environment =
            FakeEnvironment::new().with_machine_host(Observation::Fact(MachineHost::Hardware));
        assert_eq!(outcome_of(&environment, None, MACHINE_HOST), Outcome::Clean);
    }

    #[test]
    fn a_system_in_a_virtual_machine_reports_a_medium_finding() {
        let environment = FakeEnvironment::new().with_machine_host(Observation::Fact(
            MachineHost::VirtualMachine {
                detail: BoundedText::new("the kernel reports kern.hv_vmm_present=1"),
            },
        ));
        let Outcome::Finding(finding) = outcome_of(&environment, None, MACHINE_HOST) else {
            panic!("a reported monitor must report a finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
    }

    #[test]
    fn a_system_in_a_virtual_machine_carries_its_own_evidence() {
        let environment = FakeEnvironment::new().with_machine_host(Observation::Fact(
            MachineHost::VirtualMachine {
                detail: BoundedText::new("the kernel reports kern.hv_vmm_present=1"),
            },
        ));
        let Outcome::Finding(finding) = outcome_of(&environment, None, MACHINE_HOST) else {
            panic!("a reported monitor must report a finding");
        };
        assert!(matches!(
            finding.evidence(),
            Evidence::VirtualMachineHost { .. }
        ));
    }

    #[test]
    fn a_failed_machine_probe_never_reads_as_clean() {
        // The rule that the security model states: Fidelity never converts a
        // detector error into a clean result. A machine that answers nothing
        // is the case an attacker would want to read as hardware.
        let environment = FakeEnvironment::new().with_machine_host(Observation::Failed {
            detail: BoundedText::new("the kernel did not answer kern.hv_vmm_present"),
        });
        let Outcome::Finding(finding) = outcome_of(&environment, None, MACHINE_HOST) else {
            panic!("a failed probe must report a health finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Low);
        assert!(finding.evidence().is_detector_health());
    }

    #[test]
    fn a_platform_with_no_machine_probe_reports_unsupported() {
        assert!(matches!(
            outcome_of(&FakeEnvironment::new(), None, MACHINE_HOST),
            Outcome::Unsupported { .. }
        ));
    }

    #[test]
    fn a_process_whose_code_a_file_accounts_for_is_clean() {
        let environment =
            FakeEnvironment::new().with_code_origin(Observation::Fact(CodeOrigin::Accounted));
        assert_eq!(
            outcome_of(&environment, None, UNACCOUNTED_CODE),
            Outcome::Clean
        );
    }

    #[test]
    fn unaccounted_code_reports_a_medium_finding() {
        let environment =
            FakeEnvironment::new().with_code_origin(Observation::Fact(CodeOrigin::Unaccounted {
                regions: 1,
                detail: BoundedText::new("one region has no file behind it"),
            }));
        let Outcome::Finding(finding) = outcome_of(&environment, None, UNACCOUNTED_CODE) else {
            panic!("unaccounted code must report a finding");
        };
        assert_eq!(finding.strength(), SignalStrength::Medium);
    }

    #[test]
    fn unaccounted_code_carries_its_own_evidence() {
        let environment =
            FakeEnvironment::new().with_code_origin(Observation::Fact(CodeOrigin::Unaccounted {
                regions: 1,
                detail: BoundedText::new("one region has no file behind it"),
            }));
        let Outcome::Finding(finding) = outcome_of(&environment, None, UNACCOUNTED_CODE) else {
            panic!("unaccounted code must report a finding");
        };
        assert!(matches!(
            finding.evidence(),
            Evidence::UnaccountedCode { .. }
        ));
    }

    #[test]
    fn a_failed_code_probe_never_reads_as_clean() {
        let environment = FakeEnvironment::new().with_code_origin(Observation::Failed {
            detail: BoundedText::new("the process mapping table did not open"),
        });
        let Outcome::Finding(finding) = outcome_of(&environment, None, UNACCOUNTED_CODE) else {
            panic!("a failed probe must report a health finding");
        };
        assert!(finding.evidence().is_detector_health());
    }

    #[test]
    fn a_platform_with_no_code_probe_reports_unsupported() {
        assert!(matches!(
            outcome_of(&FakeEnvironment::new(), None, UNACCOUNTED_CODE),
            Outcome::Unsupported { .. }
        ));
    }
    #[test]
    fn a_region_that_turned_writable_after_start_reports_a_finding() {
        // The region keeps its first address, so the added-code rule reports
        // nothing for it. Without the protection half the process runs
        // writable code and the detector stays clean.
        let at_start = CodeRegions::new(vec![Region::new(0x1000, 0x2000, false)]);
        let now = CodeRegions::new(vec![Region::new(0x1000, 0x2000, true)]);
        let environment = FakeEnvironment::default().with_code_regions(Observation::Fact(now));

        let outcomes = Detectors::new(None, Captured::Snapshot(at_start), Captured::Unsupported)
            .scan_cheap(&environment, NOW);
        let Some((_, outcome)) = outcomes
            .iter()
            .find(|(detector, _)| *detector == RUNTIME_BASELINE)
        else {
            panic!("the baseline detector must answer")
        };
        let Outcome::Finding(finding) = outcome else {
            panic!("a protection change must produce a finding")
        };
        assert!(matches!(
            finding.evidence(),
            Evidence::CodeMadeWritable { .. }
        ));
    }
}
