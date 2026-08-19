//! The firmware identity boundary.
//!
//! The kernel parses the SMBIOS table that the firmware supplies, and it writes
//! each field as one file of text. This module reads two of them and returns
//! the text. It interprets nothing: `fidelity-formats` holds the judgment, and
//! Windows reads the same two DMTF fields out of the raw table.
//!
//! It also answers one question that the firmware cannot. A monitor that
//! supplies no SMBIOS table at all leaves both files absent, and the kernel
//! still holds the paravirtual bus that such a monitor needs. A measurement
//! put that case here rather than caution, and
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! holds it.

use std::fs;

/// Where the kernel writes who the firmware names as the maker.
const MANUFACTURER_PATH: &str = "/sys/class/dmi/id/sys_vendor";

/// Where the kernel writes what the firmware names as the product.
const PRODUCT_PATH: &str = "/sys/class/dmi/id/product_name";

/// Where the kernel lists the paravirtual devices that it holds.
const VIRTIO_PATH: &str = "/sys/bus/virtio/devices";

/// What the firmware states about the machine that runs this system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirmwareIdentity {
    /// Who the firmware names as the maker.
    pub(crate) manufacturer: String,

    /// What the firmware names as the product.
    pub(crate) product: String,
}

/// Reads the two firmware fields that name the machine.
///
/// Returns `None` when the kernel writes neither file. That is not a failure:
/// a machine whose firmware supplies no SMBIOS table has no such file, and an
/// ARM64 board is the common case. Both files carry world read permission, and
/// the two that name a serial number do not, so this never reads one.
pub(crate) fn firmware_identity() -> Option<FirmwareIdentity> {
    // A trailing newline belongs to the file rather than to the value, and a
    // prefix rule would keep it, so both sides lose it here.
    let manufacturer = fs::read_to_string(MANUFACTURER_PATH).ok()?;
    let product = fs::read_to_string(PRODUCT_PATH).ok()?;
    Some(FirmwareIdentity {
        manufacturer: manufacturer.trim().to_owned(),
        product: product.trim().to_owned(),
    })
}

/// Reports whether the kernel holds a paravirtual device.
///
/// A virtio device is one half of a contract between a guest and the monitor
/// that runs it, so nothing offers one to a system that runs on the hardware.
/// The directory exists on a kernel that carries the driver and holds no such
/// device, so the answer is what it lists rather than that it exists.
pub(crate) fn holds_a_paravirtual_device() -> bool {
    fs::read_dir(VIRTIO_PATH).is_ok_and(|mut entries| entries.next().is_some())
}

#[cfg(test)]
mod tests {
    use super::firmware_identity;

    #[test]
    fn a_stated_identity_names_a_maker() {
        // The live control for the boundary. A machine whose firmware supplies
        // no SMBIOS table states nothing at all, and that is ordinary on an
        // ARM64 board, so the test holds only where the kernel wrote the
        // files. The capability holds the control that every machine runs, and
        // `tests/platform/README.md` records what each one reported.
        let Some(identity) = firmware_identity() else {
            return;
        };
        assert!(!identity.manufacturer.is_empty());
    }
}
