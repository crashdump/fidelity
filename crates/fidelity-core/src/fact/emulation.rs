//! The facts that the emulation capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about the environment below it.
///
/// The capability answers one question: does the application run on hardware,
/// in a virtual machine, or in a simulated environment? The operating system
/// answers, because it sees that boundary. A processor flag answers a different
/// question, and
/// [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
/// excludes it on Windows for that reason.
///
/// It does not answer who selected that environment. A developer who uses a
/// virtual machine, simulator, or emulator reports the same fact on every clean
/// run. The strength states how much the fact is worth, and the host selects
/// its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineHost {
    /// The system reports that it runs on the hardware itself.
    Hardware,

    /// The system reports that a virtual machine monitor runs it.
    VirtualMachine {
        /// Which interface reported it, in text that holds no application data.
        detail: BoundedText,
    },

    /// The application runs in a simulator or an emulator.
    Simulated {
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

    #[test]
    fn a_simulated_environment_differs_from_a_virtual_machine() {
        assert_ne!(
            MachineHost::Simulated {
                detail: BoundedText::new("the system reports an emulator"),
            },
            MachineHost::VirtualMachine {
                detail: BoundedText::new("the system reports a monitor"),
            }
        );
    }
}
