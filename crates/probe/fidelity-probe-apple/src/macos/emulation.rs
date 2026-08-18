//! The machine host on macOS.
//!
//! The kernel states whether a virtual machine monitor runs it, in one value.
//! `docs/plan/04-detectors-and-platforms.md` holds the strength and the
//! coverage limits, and `crate::sys::vmm` holds the interface and the name
//! that it must not be confused with.

use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_types::BoundedText;

use super::MacEnvironment;
use crate::sys::vmm::{self, Verdict};

/// What a reported virtual machine states.
const MONITOR_PRESENT: &str =
    "the kernel reports kern.hv_vmm_present=1, so a virtual machine monitor runs this system";

impl Emulation for MacEnvironment {
    fn machine_host(&self) -> Observation<MachineHost> {
        match vmm::present() {
            Verdict::Hardware => Observation::Fact(MachineHost::Hardware),
            Verdict::VirtualMachine => Observation::Fact(MachineHost::VirtualMachine {
                detail: BoundedText::new(MONITOR_PRESENT),
            }),
            Verdict::Absent(reason) => Observation::Unsupported { reason },
            Verdict::Failed(detail) => Observation::failed(detail),
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, Observation};

    use super::MacEnvironment;

    #[test]
    fn the_probe_reads_the_machine_of_this_system() {
        // The live control. Which fact it reports depends on the machine, and
        // both machines sit in the test record. A failure is what must never
        // happen, because macOS 15 and later hold this value.
        let observation = MacEnvironment::new().machine_host();
        assert!(
            matches!(observation, Observation::Fact(_)),
            "{observation:?}"
        );
    }
}
