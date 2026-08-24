use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// A nonhardware environment runs the system or the application.
pub const MACHINE_HOST: Detector =
    Detector::new(7, "virtualization.machine_host", Category::Virtualization);

/// The strength of a reported nonhardware environment.
///
/// `Medium`, and not `High`, for the two reasons that the
/// [signal model](../../../../docs/plan/04-detectors-and-platforms.md) states.
/// Both clauses of `Medium` apply, and either one alone would be enough.
///
/// The first is the benign case, and it is common. A developer who uses a
/// virtual machine, simulator, or emulator reports this on every clean run. A
/// build machine and a virtual desktop report it too.
///
/// The second is the bypass. One kernel value answers, and a root actor on the
/// guest replaces it. The detector states what the system says about itself,
/// and it never claims to have proved it.
const NON_HARDWARE_STRENGTH: SignalStrength = SignalStrength::Medium;

/// Interprets what the system reports about the machine below it.
pub(crate) fn machine_host(environment: &(impl Emulation + ?Sized), now_unix_ms: u64) -> Outcome {
    match environment.machine_host() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(MachineHost::Hardware) => Outcome::Clean,
        Observation::Fact(MachineHost::VirtualMachine { detail }) => {
            Outcome::Finding(Finding::new(
                MACHINE_HOST,
                NON_HARDWARE_STRENGTH,
                Evidence::VirtualMachineHost { detail },
                now_unix_ms,
            ))
        }
        Observation::Fact(MachineHost::Simulated { detail }) => Outcome::Finding(Finding::new(
            MACHINE_HOST,
            NON_HARDWARE_STRENGTH,
            Evidence::SimulatedEnvironment { detail },
            now_unix_ms,
        )),
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        MACHINE_HOST,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
