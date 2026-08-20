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

use std::{fs, io};

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
/// Returns `Ok(None)` when the kernel writes neither file. That is not a
/// failure: a machine whose firmware supplies no SMBIOS table has no such
/// file, and an ARM64 board is the common case. Both files carry world read
/// permission, and the two that name a serial number do not, so this never
/// reads one.
///
/// Returns `Err` for any read error other than a file that is absent. A read
/// that failed must not read as a machine with no identity, because the caller
/// then reports the hardware and the detector records a clean result after a
/// failed check. A container that masks `/sys` returns a permission error, so
/// this case is real.
pub(crate) fn firmware_identity() -> io::Result<Option<FirmwareIdentity>> {
    let (Some(manufacturer), Some(product)) =
        (read_field(MANUFACTURER_PATH)?, read_field(PRODUCT_PATH)?)
    else {
        return Ok(None);
    };
    Ok(Some(FirmwareIdentity {
        manufacturer,
        product,
    }))
}

/// Reads one firmware field, and separates an absent file from a read error.
///
/// A file that the kernel did not write is `Ok(None)`, which is ordinary. Any
/// other error is an `Err`, so the caller reports a failed check rather than a
/// machine with no firmware identity.
fn read_field(path: &str) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        // A trailing newline belongs to the file rather than to the value, and
        // a prefix rule would keep it, so the value loses it here.
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reports whether the kernel holds a paravirtual device.
///
/// A virtio device is one half of a contract between a guest and the monitor
/// that runs it, so nothing offers one to a system that runs on the hardware.
/// The directory exists on a kernel that carries the driver and holds no such
/// device, so the answer is what it lists rather than that it exists.
///
/// Returns `Ok(false)` when the directory is absent, which is ordinary on a
/// kernel with no virtio driver. Any other error is an `Err`, so the caller
/// reports a failed check rather than a machine with no paravirtual bus.
pub(crate) fn holds_a_paravirtual_device() -> io::Result<bool> {
    match fs::read_dir(VIRTIO_PATH) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::{firmware_identity, read_field};

    #[test]
    fn a_stated_identity_names_a_maker() {
        // The live control for the boundary. A machine whose firmware supplies
        // no SMBIOS table states nothing at all, and that is ordinary on an
        // ARM64 board, so the test holds only where the kernel wrote the
        // files. The capability holds the control that every machine runs, and
        // `tests/platform/README.md` records what each one reported.
        let Ok(Some(identity)) = firmware_identity() else {
            return;
        };
        assert!(!identity.manufacturer.is_empty());
    }

    #[test]
    fn an_absent_field_reads_as_none() {
        // A file that the kernel never wrote is ordinary, and it must read as
        // an absent field rather than as a failed read. An ARM64 board that
        // supplies no SMBIOS table is the common case.
        let path = env::temp_dir().join(format!("fidelity-dmi-absent-{}", std::process::id()));
        let Some(path) = path.to_str() else {
            panic!("the temp path holds no UTF-8");
        };
        assert!(matches!(read_field(path), Ok(None)));
    }

    #[test]
    fn a_read_error_is_not_an_absent_field() {
        // A read that failed must reach the caller as an error, so the detector
        // reports its health rather than the hardware. An `Option` return
        // merged this case with an absent file until 2026-08-20, and a masked
        // `/sys` then read as a machine with no firmware. This test holds a
        // regular file and reads a path below it, which fails with `ENOTDIR`,
        // and it asserts the error survives.
        let file = env::temp_dir().join(format!("fidelity-dmi-file-{}", std::process::id()));
        let Ok(()) = fs::write(&file, b"x") else {
            panic!("the test could not write the temp file");
        };
        let child = file.join("sys_vendor");
        let Some(child) = child.to_str() else {
            panic!("the temp path holds no UTF-8");
        };
        let result = read_field(child);
        let _ = fs::remove_file(&file);
        assert!(result.is_err());
    }
}
