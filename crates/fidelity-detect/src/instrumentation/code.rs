use fidelity_core::{CodeOrigin, Injection, Observation};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// This process executes code that no file accounts for.
pub const UNACCOUNTED_CODE: Detector = Detector::new(
    4,
    "instrumentation.unaccounted_code",
    Category::Instrumentation,
);

/// The strength of code that no file accounts for.
///
/// `Medium`, and the reason is a measurement rather than caution. A loader
/// maps code from a file, so executable memory with no file behind it is
/// direct evidence that code arrived another way. Measured on Debian and on
/// Android: a plain process and a process that runs a just-in-time compiler
/// both hold none, because the kernel names a run-time code cache instead of
/// leaving it anonymous.
///
/// It stays below `High` because one benign case is open. A host whose process
/// runs a compiler that does not name its regions holds them legitimately, and
/// a desktop web view is the case that matters for this project. The
/// [plan](../../../../docs/plan/04-detectors-and-platforms.md) states that
/// measurement as required clean-control work, and `High` waits for it.
const UNACCOUNTED_STRENGTH: SignalStrength = SignalStrength::Medium;

/// Interprets what the operating system reports about the code in the process.
pub(crate) fn unaccounted_code(
    environment: &(impl Injection + ?Sized),
    now_unix_ms: u64,
) -> Outcome {
    match environment.code_origin() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(CodeOrigin::Accounted) => Outcome::Clean,
        Observation::Fact(CodeOrigin::Unaccounted { detail, .. }) => {
            Outcome::Finding(Finding::new(
                UNACCOUNTED_CODE,
                UNACCOUNTED_STRENGTH,
                Evidence::UnaccountedCode { detail },
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
        UNACCOUNTED_CODE,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
