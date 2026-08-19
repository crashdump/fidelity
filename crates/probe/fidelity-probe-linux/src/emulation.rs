//! The emulation capability on Linux.
//!
//! Linux answers this in two places, and the capability reads both because
//! neither one covers the other. The firmware names the machine, and a monitor
//! that supplies no firmware table still needs the paravirtual bus.
//!
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! holds the strength and the coverage limits.

use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_formats::smbios::vendor::names_a_monitor;
use fidelity_types::BoundedText;

use crate::LinuxEnvironment;
use crate::sys::dmi;

/// What a paravirtual device reports.
///
/// The text names the bus and no device, because the count and the names of
/// the devices state which monitor runs the system and the finding needs
/// neither.
const PARAVIRTUAL: &str = "the kernel holds a virtio device, which needs a monitor to answer it";

impl Emulation for LinuxEnvironment {
    fn machine_host(&self) -> Observation<MachineHost> {
        // The firmware answers first, because it names the monitor and the bus
        // only states that one is there.
        if let Some(field) = named_monitor() {
            return Observation::Fact(MachineHost::VirtualMachine {
                detail: BoundedText::new(format!("the firmware names the machine {field}")),
            });
        }

        if dmi::holds_a_paravirtual_device() {
            return Observation::Fact(MachineHost::VirtualMachine {
                detail: BoundedText::new(PARAVIRTUAL),
            });
        }

        // Neither source answered. A machine that runs on the hardware reaches
        // this, and so does a monitor that publishes no firmware identity and
        // offers no paravirtual device. The plan states that limit, and the
        // strength of the detector states what the answer is worth.
        Observation::Fact(MachineHost::Hardware)
    }
}

/// The firmware field that names a monitor, when the firmware states one.
///
/// The field owns its text, because the judgment borrows from the two files
/// that the boundary read and the caller outlives both.
fn named_monitor() -> Option<String> {
    let identity = dmi::firmware_identity()?;
    names_a_monitor(&identity.manufacturer, &identity.product).map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, MachineHost, Observation};

    use super::LinuxEnvironment;

    #[test]
    fn the_probe_reads_the_machine_that_runs_this_system() {
        // The live control. Which of the two facts it gives depends on the
        // machine, and `tests/platform/README.md` records both. This capability
        // reports no failure at all: an absent source is an answer here, not a
        // broken read, so the only wrong result is a panic.
        let observation = LinuxEnvironment::new().machine_host();
        assert!(
            matches!(
                observation,
                Observation::Fact(MachineHost::Hardware | MachineHost::VirtualMachine { .. })
            ),
            "{observation:?}"
        );
    }
}
