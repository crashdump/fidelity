//! The emulation capability on Windows.
//!
//! The firmware names the machine, and this reads that name. It does not read
//! the processor flag, which
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! excludes, because ordinary VBS, Hyper-V, WSL2, and Windows Sandbox all set
//! it and a large share of clean Windows machines run one of those.
//!
//! Linux reads the same two fields of the same DMTF structure, so both
//! platforms share one reader and one list of names.

use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_formats::smbios::system::system_information;
use fidelity_formats::smbios::vendor::names_a_monitor;
use fidelity_types::BoundedText;

use crate::WindowsEnvironment;
use crate::sys::firmware;

/// What a table the reader cannot walk reports.
const UNREADABLE: &str = "the firmware table stated no System Information structure";

impl Emulation for WindowsEnvironment {
    fn machine_host(&self) -> Observation<MachineHost> {
        let table = match firmware::smbios_table() {
            Ok(table) => table,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        let Some(identity) = system_information(&table) else {
            return Observation::Failed {
                detail: BoundedText::new(UNREADABLE),
            };
        };

        match names_a_monitor(identity.manufacturer, identity.product) {
            Some(field) => Observation::Fact(MachineHost::VirtualMachine {
                detail: BoundedText::new(format!("the firmware names the machine {field}")),
            }),
            // The firmware names a maker that no monitor writes. A monitor that
            // states the name of the hardware it imitates reaches this too, and
            // the plan holds that coverage limit.
            None => Observation::Fact(MachineHost::Hardware),
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, MachineHost, Observation};

    use super::WindowsEnvironment;

    #[test]
    fn the_probe_reads_the_machine_that_runs_this_system() {
        // The live control. Which of the two facts it gives depends on the
        // machine, and `tests/platform/README.md` records what each reported.
        // A failure is what must never happen here, because every machine that
        // runs Windows carries a firmware table.
        let observation = WindowsEnvironment::new().machine_host();
        assert!(
            matches!(
                observation,
                Observation::Fact(MachineHost::Hardware | MachineHost::VirtualMachine { .. })
            ),
            "{observation:?}"
        );
    }
}
