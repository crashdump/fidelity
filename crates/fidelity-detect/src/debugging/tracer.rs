use fidelity_core::{Observation, Tracer, TracerState};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// A debugger or a tracer holds this process.
pub const TRACER_PRESENT: Detector =
    Detector::new(3, "debugging.tracer_present", Category::Debugging);

/// The strength of a reported tracer.
///
/// `Medium`, and not `High`, for two reasons that the
/// [signal model](../../../../docs/plan/04-detectors-and-platforms.md) states.
///
/// The first is the bypass. macOS reports this state through one documented
/// interface, and a call to that interface is the best known target in the
/// whole category. An attacker who already runs inside the process replaces
/// the answer with one call site, which is the definition of a meaningful
/// user-mode bypass. A second independent source would change the answer,
/// because a disagreement between two sources is itself evidence.
///
/// The second is the benign case. A developer who attaches a debugger to a
/// build under test trips this on every run. Nobody has measured how a
/// profiler, a crash reporter, or an enterprise agent behaves against it, and
/// the research notes list that measurement as required work. `High` needs a
/// benign explanation that is structurally rare, and that claim needs the
/// measurement first.
const PRESENT_STRENGTH: SignalStrength = SignalStrength::Medium;

/// Interprets what the operating system reports about a tracer.
pub(crate) fn tracer_present(environment: &(impl Tracer + ?Sized), now_unix_ms: u64) -> Outcome {
    match environment.tracer_state() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(TracerState::Absent) => Outcome::Clean,
        Observation::Fact(TracerState::Present { detail }) => Outcome::Finding(Finding::new(
            TRACER_PRESENT,
            PRESENT_STRENGTH,
            Evidence::TracerPresent { detail },
            now_unix_ms,
        )),
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        TRACER_PRESENT,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
