use fidelity_core::{Device, Observation, SystemBuild};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// No vendor released the system build that runs now.
pub const SYSTEM_BUILD: Detector = Detector::new(
    6,
    "device_compromise.system_build",
    Category::DeviceCompromise,
);

/// The strength of a development build.
///
/// `Medium`, and not `High`, for the two reasons that the
/// [signal model](../../../../docs/plan/04-detectors-and-platforms.md) states.
/// Both clauses of `Medium` apply, and either one alone would be enough.
///
/// The first is the benign case, and it is common. An emulator, a developer's
/// own device, and an engineering build all report this on every clean run.
/// Measured on 2026-08-10, a Google APIs emulator image reports it and a Play
/// Store image does not, so the two system images are the clean control and
/// the hostile control for the same code.
///
/// The second is the bypass. The property store is writable by a root user,
/// and the tools that take root rewrite it. A system that reports a released
/// build may therefore be rooted and quiet, which is the coverage limit that
/// the plan records. The detector states what the system says about itself,
/// and it never claims to have proved it.
const DEVELOPMENT_STRENGTH: SignalStrength = SignalStrength::Medium;

/// Interprets what the system reports about its own build.
pub(crate) fn system_build(environment: &(impl Device + ?Sized), now_unix_ms: u64) -> Outcome {
    match environment.system_build() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(SystemBuild::Released) => Outcome::Clean,
        Observation::Fact(SystemBuild::Development { detail }) => Outcome::Finding(Finding::new(
            SYSTEM_BUILD,
            DEVELOPMENT_STRENGTH,
            Evidence::DevelopmentBuild { detail },
            now_unix_ms,
        )),
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        SYSTEM_BUILD,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
