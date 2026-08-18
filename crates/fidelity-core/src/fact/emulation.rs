//! The facts that the emulation capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about the machine below it.
///
/// The capability answers one question: does a virtual machine monitor run
/// this system? The kernel answers, because the kernel is the one part that
/// sees the boundary. A processor flag answers a different question, and
/// [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
/// excludes it on Windows for that reason.
///
/// It does not answer whether an attacker put the system in that machine. A
/// developer who runs the whole system in a virtual machine reports the same
/// fact on every clean run, so the strength states how much the fact is worth
/// and the host decides what to do with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineHost {
    /// The system reports that it runs on the hardware itself.
    Hardware,

    /// The system reports that a virtual machine monitor runs it.
    VirtualMachine {
        /// Which interface reported it, in text that holds no application data.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::MachineHost;

    #[test]
    fn a_virtual_machine_keeps_its_detail() {
        let host = MachineHost::VirtualMachine {
            detail: BoundedText::new("the kernel reports kern.hv_vmm_present=1"),
        };
        assert_eq!(
            host,
            MachineHost::VirtualMachine {
                detail: BoundedText::new("the kernel reports kern.hv_vmm_present=1"),
            }
        );
    }

    #[test]
    fn hardware_differs_from_a_virtual_machine() {
        assert_ne!(
            MachineHost::Hardware,
            MachineHost::VirtualMachine {
                detail: BoundedText::new("the kernel reports kern.hv_vmm_present=1"),
            }
        );
    }
}
