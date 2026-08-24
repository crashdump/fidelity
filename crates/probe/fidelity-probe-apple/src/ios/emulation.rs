//! The machine host on iOS.

use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_types::BoundedText;

use super::IosEnvironment;
use crate::sys::machine;

impl Emulation for IosEnvironment {
    fn machine_host(&self) -> Observation<MachineHost> {
        match machine::name() {
            Ok(name) => classify(&name).map_or_else(Observation::failed, Observation::Fact),
            Err(detail) => Observation::failed(detail),
        }
    }
}

/// What a simulator machine name states.
const HOST_ARCHITECTURE: &str =
    "hw.machine reports the host architecture instead of an iOS product name";

/// Classifies the machine name that the iOS kernel reports.
fn classify(name: &str) -> Result<MachineHost, &'static str> {
    if name.starts_with("iPhone") || name.starts_with("iPad") || name.starts_with("iPod") {
        return Ok(MachineHost::Hardware);
    }
    if matches!(name, "arm64" | "x86_64") {
        return Ok(MachineHost::Simulated {
            detail: BoundedText::new(HOST_ARCHITECTURE),
        });
    }
    Err("hw.machine names no known iOS device or simulator architecture")
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, MachineHost, Observation};

    use super::{IosEnvironment, classify};

    #[test]
    fn an_iphone_is_hardware() {
        assert_eq!(classify("iPhone13,3"), Ok(MachineHost::Hardware));
    }

    #[test]
    fn an_ipad_is_hardware() {
        assert_eq!(classify("iPad16,3"), Ok(MachineHost::Hardware));
    }

    #[test]
    fn a_host_architecture_is_a_simulated_environment() {
        assert!(matches!(
            classify("arm64"),
            Ok(MachineHost::Simulated { .. })
        ));
        assert!(matches!(
            classify("x86_64"),
            Ok(MachineHost::Simulated { .. })
        ));
    }

    #[test]
    fn an_unknown_name_is_a_failure() {
        assert!(classify("future-device").is_err());
    }

    #[test]
    fn the_simulator_reports_a_simulated_environment() {
        let observation = IosEnvironment::new().machine_host();
        assert!(
            matches!(
                observation,
                Observation::Fact(MachineHost::Simulated { .. })
            ),
            "{observation:?}"
        );
    }
}
