//! The firmware table boundary.
//!
//! Windows hands the raw SMBIOS table to any process, through
//! `GetSystemFirmwareTable`, which Microsoft documents at
//! <https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable>.
//! Linux parses the same table in the kernel and writes each field as a file,
//! so both platforms read the same two DMTF fields and share one reader in
//! `fidelity-formats`.
//!
//! This module returns the bytes and interprets none of them.
//!
//! It reads the firmware rather than the processor. The processor flag that
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! excludes reports every machine that runs VBS, Hyper-V, WSL2, or Windows
//! Sandbox, and a large share of clean Windows machines run one of those. What
//! the firmware states about the maker of the machine is a different question.

use core::ffi::c_void;

/// The provider that answers with the raw SMBIOS table.
///
/// Microsoft states the signature as the four characters `RSMB`, and the call
/// takes them as one big-endian value.
const RAW_SMBIOS: u32 = u32::from_be_bytes(*b"RSMB");

/// The header that the provider writes before the table.
///
/// `RawSMBIOSData` holds four bytes of version, then the length as four more.
/// The structures start after it, and that is what the shared reader takes.
const HEADER_BYTES: usize = 8;

/// The largest table this reads.
///
/// A real table is a few hundred bytes: the guest that this project builds
/// reports 383. The bound stops a firmware that states a size no allocation
/// should follow.
/// [State and budgets](../../../../docs/plan/07-state-and-budgets.md) states
/// the rule that this keeps: the cost of a scan grows with nothing that an
/// attacker chooses.
const MOST_BYTES: u32 = 1 << 20;

unsafe extern "system" {
    fn GetSystemFirmwareTable(provider: u32, table: u32, buffer: *mut c_void, size: u32) -> u32;
}

/// Reads the structure area of the raw SMBIOS table.
///
/// # Errors
///
/// Returns the reason the read failed. A machine whose firmware supplies no
/// table answers zero here, and the caller reports that as a gap rather than
/// as a clean result.
pub(crate) fn smbios_table() -> Result<Vec<u8>, &'static str> {
    // SAFETY: a null buffer with a zero size asks for the size only, which the
    // documented call answers without a write.
    let size = unsafe { GetSystemFirmwareTable(RAW_SMBIOS, 0, std::ptr::null_mut(), 0) };

    if size == 0 {
        return Err("the firmware of this machine supplies no SMBIOS table");
    }
    if size > MOST_BYTES {
        return Err("the firmware reported an SMBIOS table above the limit that a probe reads");
    }

    let mut buffer = vec![0_u8; size as usize];

    // SAFETY: `buffer` holds `size` bytes and the call takes that same count,
    // so it writes inside the allocation. The call reads nothing from it.
    let written = unsafe {
        GetSystemFirmwareTable(RAW_SMBIOS, 0, buffer.as_mut_ptr().cast::<c_void>(), size)
    };

    if written == 0 || written > size {
        return Err("the firmware table did not fit the size that the call reported");
    }
    buffer.truncate(written as usize);

    // The structures follow the header, and the shared reader takes those
    // alone, because Linux never sees this header at all.
    if buffer.len() <= HEADER_BYTES {
        return Err("the firmware table holds a header and no structure");
    }
    Ok(buffer.split_off(HEADER_BYTES))
}

#[cfg(test)]
mod tests {
    use super::smbios_table;

    #[test]
    fn the_firmware_of_this_machine_states_a_table() {
        // The boundary control. Every machine that this project reaches states
        // one, and the guest that `vm.sh windows` builds reports 383 bytes.
        let Ok(table) = smbios_table() else {
            panic!("the firmware stated no readable SMBIOS table")
        };
        assert!(!table.is_empty());
    }
}
