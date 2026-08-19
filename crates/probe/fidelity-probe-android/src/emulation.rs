//! The machine that runs the system, on Android.
//!
//! Android states this in its own property store, and the same boundary that
//! answers `device` answers it. Three properties carry it, and each one comes
//! from a different part of the system: the bootloader states one, the build
//! states another, and the board states the third.
//!
//! [Detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! holds the strength and the coverage limits.

use core::ffi::CStr;

use fidelity_core::{Emulation, MachineHost, Observation};
use fidelity_types::BoundedText;

use super::AndroidEnvironment;
use crate::sys::property;

/// What the bootloader states about the machine below the system.
const BOOT: &CStr = c"ro.boot.qemu";

/// What the build states about the shape of the product.
const CHARACTERISTICS: &CStr = c"ro.build.characteristics";

/// What the system names as its board.
const BOARD: &CStr = c"ro.hardware";

/// What `ro.boot.qemu` holds on a system that an emulator booted.
const BOOTED_BY_AN_EMULATOR: &str = "1";

/// What `ro.build.characteristics` names on a build for an emulator.
///
/// The property holds a comma-separated list, so the rule looks inside it. A
/// released device names a shape such as `nosdcard` or `tablet` there.
const EMULATOR: &str = "emulator";

/// The boards that the Android emulator supplies.
///
/// `goldfish` is the older virtual board and `ranchu` is the current one.
/// Measured on 2026-08-19: an Android 37 emulator names `ranchu`.
const VIRTUAL_BOARDS: [&str; 2] = ["goldfish", "ranchu"];

/// What the boot property reports.
const BOOT_STATES_AN_EMULATOR: &str = "the bootloader reports ro.boot.qemu=1";

/// What the build property reports.
const BUILD_STATES_AN_EMULATOR: &str = "the build names ro.build.characteristics=emulator";

/// What the board property reports.
const BOARD_IS_VIRTUAL: &str = "the system names a board that only an emulator supplies";

/// What an empty property store reports.
const NO_PROPERTY: &str = "the property store did not state ro.hardware";

impl Emulation for AndroidEnvironment {
    fn machine_host(&self) -> Observation<MachineHost> {
        match judge(
            property::read(BOOT).as_deref(),
            property::read(CHARACTERISTICS).as_deref(),
            property::read(BOARD).as_deref(),
        ) {
            Ok(host) => Observation::Fact(host),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Decides what the three properties state about the machine.
///
/// The decision is a plain function, so a test proves every answer on one
/// system. Only an emulator reaches the reported answers here, and this project
/// owns no physical device, so `tests/platform/README.md` records the clean
/// control as a gap.
///
/// # Errors
///
/// Returns the reason when no property names an emulator and the store did not
/// state the board. Every Android system names a board, so an absent one is a
/// failed read and never a machine that runs on the hardware.
fn judge(
    boot: Option<&str>,
    characteristics: Option<&str>,
    board: Option<&str>,
) -> Result<MachineHost, &'static str> {
    // One property alone states an emulator, so each answer stands whatever
    // the other two say, and a failed read of them changes nothing.
    if boot == Some(BOOTED_BY_AN_EMULATOR) {
        return Ok(virtual_machine(BOOT_STATES_AN_EMULATOR));
    }
    if characteristics.is_some_and(names_an_emulator) {
        return Ok(virtual_machine(BUILD_STATES_AN_EMULATOR));
    }
    if board.is_some_and(|name| VIRTUAL_BOARDS.contains(&name)) {
        return Ok(virtual_machine(BOARD_IS_VIRTUAL));
    }
    // Only the hardware answer is left, and it needs the store to have
    // answered at all. Reporting it from an empty store would turn a broken
    // probe into a clean control.
    if board.is_none() {
        return Err(NO_PROPERTY);
    }
    Ok(MachineHost::Hardware)
}

/// Reports whether the shape list names an emulator.
fn names_an_emulator(characteristics: &str) -> bool {
    characteristics.split(',').any(|shape| shape == EMULATOR)
}

/// Builds the fact that a reported emulator carries.
fn virtual_machine(detail: &'static str) -> MachineHost {
    MachineHost::VirtualMachine {
        detail: BoundedText::new(detail),
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Emulation, MachineHost, Observation};

    use super::{AndroidEnvironment, judge};

    #[test]
    fn the_probe_reads_the_machine_that_runs_this_system() {
        // The live control. Every Android system this project reaches is an
        // emulator, so this reports one, and a failure is what must never
        // happen because every Android system names a board.
        let observation = AndroidEnvironment::new().machine_host();
        assert!(
            matches!(observation, Observation::Fact(_)),
            "{observation:?}"
        );
    }

    #[test]
    fn a_released_device_reports_the_hardware() {
        let Ok(host) = judge(None, Some("nosdcard"), Some("qcom")) else {
            panic!("a stated board is never a failed read")
        };
        assert_eq!(host, MachineHost::Hardware);
    }

    #[test]
    fn the_boot_property_reports_an_emulator() {
        let Ok(host) = judge(Some("1"), Some("nosdcard"), Some("qcom")) else {
            panic!("a stated board is never a failed read")
        };
        assert!(matches!(host, MachineHost::VirtualMachine { .. }));
    }

    #[test]
    fn the_build_property_reports_an_emulator() {
        let Ok(host) = judge(None, Some("emulator"), Some("qcom")) else {
            panic!("a stated board is never a failed read")
        };
        assert!(matches!(host, MachineHost::VirtualMachine { .. }));
    }

    #[test]
    fn the_virtual_board_reports_an_emulator() {
        let Ok(host) = judge(None, Some("nosdcard"), Some("ranchu")) else {
            panic!("a stated board is never a failed read")
        };
        assert!(matches!(host, MachineHost::VirtualMachine { .. }));
    }

    #[test]
    fn a_shape_list_that_holds_the_marker_reports_an_emulator() {
        // The property holds a list, and a released build states more than one
        // shape in it, so a rule that compared the whole value would miss this.
        let Ok(host) = judge(None, Some("nosdcard,emulator"), Some("qcom")) else {
            panic!("a stated board is never a failed read")
        };
        assert!(matches!(host, MachineHost::VirtualMachine { .. }));
    }

    #[test]
    fn a_shape_that_only_holds_the_marker_reports_the_hardware() {
        // The rule takes one whole shape out of the list. A product that names
        // itself `emulator-ready` is not an emulator.
        let Ok(host) = judge(None, Some("emulator-ready"), Some("qcom")) else {
            panic!("a stated board is never a failed read")
        };
        assert_eq!(host, MachineHost::Hardware);
    }

    #[test]
    fn a_board_that_no_survey_covers_reports_the_hardware() {
        // The list names the two boards it knows, and an unknown name is not
        // evidence. A third-party emulator supplies its own board and reports
        // nothing here, which is the coverage limit that the plan states.
        let Ok(host) = judge(None, Some("nosdcard"), Some("vbox86")) else {
            panic!("a stated board is never a failed read")
        };
        assert_eq!(host, MachineHost::Hardware);
    }

    #[test]
    fn an_empty_property_store_reports_a_health_finding() {
        // Never the hardware. A store that states nothing is a failed read,
        // and Fidelity never reports a failed read as a clean result.
        assert!(judge(None, None, None).is_err());
    }

    #[test]
    fn one_stated_property_is_enough_to_decide() {
        let Ok(host) = judge(Some("1"), None, None) else {
            panic!("one stated property is never a failed read")
        };
        assert!(matches!(host, MachineHost::VirtualMachine { .. }));
    }
}
