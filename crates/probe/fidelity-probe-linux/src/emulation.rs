//! The emulation capability on Linux.
//!
//! Linux answers this in two places, and the capability reads both because
//! neither one covers the other. The firmware names the machine, and a monitor
//! that supplies no firmware table still needs the paravirtual bus.
//!
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! holds the strength and the coverage limits.

use std::io;

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
        match named_monitor() {
            Ok(Some(field)) => {
                return Observation::Fact(MachineHost::VirtualMachine {
                    detail: BoundedText::new(format!("the firmware names the machine {field}")),
                });
            }
            Ok(None) => {}
            // A read that failed must not read as a machine that named no
            // monitor, because the detector would then report the hardware
            // after a failed check. A failed read reports its own health.
            Err(error) => return failed(&error),
        }

        match dmi::holds_a_paravirtual_device() {
            Ok(true) => {
                return Observation::Fact(MachineHost::VirtualMachine {
                    detail: BoundedText::new(PARAVIRTUAL),
                });
            }
            Ok(false) => {}
            Err(error) => return failed(&error),
        }

        // Neither source answered. A machine that runs on the hardware reaches
        // this, and so does a monitor that publishes no firmware identity and
        // offers no paravirtual device. The plan states that limit, and the
        // strength of the detector states what the answer is worth.
        Observation::Fact(MachineHost::Hardware)
    }
}

/// Reports a firmware read that failed, so the detector states its health.
fn failed(error: &io::Error) -> Observation<MachineHost> {
    Observation::Failed {
        detail: BoundedText::new(format!("the firmware read failed: {error}")),
    }
}

/// The firmware field that names a monitor, when the firmware states one.
///
/// The field owns its text, because the judgment borrows from the two files
/// that the boundary read and the caller outlives both.
fn named_monitor() -> io::Result<Option<String>> {
    let Some(identity) = dmi::firmware_identity()? else {
        return Ok(None);
    };
    Ok(names_a_monitor(&identity.manufacturer, &identity.product).map(ToOwned::to_owned))
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, MachineHost, Observation};

    use super::LinuxEnvironment;

    #[test]
    fn the_probe_reads_the_machine_that_runs_this_system() {
        // The live control. Which of the two facts it gives depends on the
        // machine, and `tests/platform/README.md` records both. An absent
        // source is an answer here and not a broken read, so a machine that
        // reads its firmware reports a fact. A read that failed reports its
        // health instead, and this machine reads its firmware, so a `Failed`
        // here is a defect that this control catches.
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
