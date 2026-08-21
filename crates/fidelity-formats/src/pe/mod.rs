//! Pure readers for Portable Executable image boundaries.
//!
//! A mapped image uses relative virtual addresses as slice offsets. A file
//! uses a file offset for its certificate table. Both readers validate every
//! offset before they return data.

/// The DOS signature at the start of a PE image.
const DOS_SIGNATURE: u16 = 0x5a4d;

/// The PE signature after the DOS stub.
const NT_SIGNATURE: u32 = 0x0000_4550;

/// The optional-header magic for a 64-bit PE image.
const OPTIONAL_MAGIC_64: u16 = 0x20b;

/// The offset of `e_lfanew` in the DOS header.
const E_LFANEW: usize = 60;

/// The size of the PE signature and file header.
const OPTIONAL_FROM_NT: usize = 24;

/// The offset of the optional-header size in the file header.
const OPTIONAL_SIZE_FROM_NT: usize = 20;

/// The data-directory offset in a PE32+ optional header.
const DATA_DIRECTORY: usize = 112;

/// The data-directory count offset in a PE32+ optional header.
const DIRECTORY_COUNT: usize = 108;

/// The import-table directory index.
const IMPORT_DIRECTORY: usize = 1;

/// The certificate-table directory index.
const CERTIFICATE_DIRECTORY: usize = 4;

/// The size of one data-directory entry.
const DIRECTORY_ENTRY: usize = 8;

/// The size of one import descriptor.
const IMPORT_DESCRIPTOR: usize = 20;

/// Reads the mapped import slots of a 64-bit PE image.
///
/// The slice must hold the complete mapped image. Relative virtual addresses
/// therefore select slice offsets. The return pairs contain the absolute slot
/// address and its current value.
///
/// Returns `None` for an absent, unsupported, or malformed import table.
#[must_use]
pub fn mapped_import_slots(
    image: &[u8],
    base_address: u64,
    most_slots: usize,
) -> Option<Vec<(u64, u64)>> {
    let optional = optional_header(image)?;
    let (directory_rva, directory_size) = directory(optional, IMPORT_DIRECTORY)?;
    let directory_start = usize::try_from(directory_rva).ok()?;
    let directory_size = usize::try_from(directory_size).ok()?;
    let directory_end = directory_start.checked_add(directory_size)?;
    image.get(directory_start..directory_end)?;

    let mut slots = Vec::new();
    let mut descriptor = directory_start;
    let mut found_end = false;
    while descriptor.checked_add(IMPORT_DESCRIPTOR)? <= directory_end {
        let lookup = read_u32(image, descriptor)?;
        let name = read_u32(image, descriptor.checked_add(12)?)?;
        let address_table = read_u32(image, descriptor.checked_add(16)?)?;
        if name == 0 && address_table == 0 {
            found_end = true;
            break;
        }
        if address_table == 0 {
            return None;
        }

        let count_table = if lookup == 0 { address_table } else { lookup };
        let mut index = 0_usize;
        loop {
            if slots.len() >= most_slots {
                return Some(slots);
            }
            let delta = index.checked_mul(core::mem::size_of::<u64>())?;
            let count_offset = usize::try_from(count_table).ok()?.checked_add(delta)?;
            if read_u64(image, count_offset)? == 0 {
                break;
            }
            let slot_offset = usize::try_from(address_table).ok()?.checked_add(delta)?;
            let value = read_u64(image, slot_offset)?;
            let slot = base_address.checked_add(u64::try_from(slot_offset).ok()?)?;
            slots.push((slot, value));
            index = index.checked_add(1)?;
        }

        descriptor = descriptor.checked_add(IMPORT_DESCRIPTOR)?;
    }

    if found_end && !slots.is_empty() {
        Some(slots)
    } else {
        None
    }
}

/// Reads the certificate table of a 64-bit PE file.
///
/// The PE format stores this directory address as a file offset. Other data
/// directories use relative virtual addresses.
///
/// Returns `None` when the table is absent or outside the file.
#[must_use]
pub fn certificate_table(image: &[u8]) -> Option<&[u8]> {
    let optional = optional_header(image)?;
    let (offset, size) = directory(optional, CERTIFICATE_DIRECTORY)?;
    if offset == 0 || size == 0 {
        return None;
    }
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    image.get(start..end)
}

/// Reads and validates the 64-bit optional header.
fn optional_header(image: &[u8]) -> Option<&[u8]> {
    if read_u16(image, 0)? != DOS_SIGNATURE {
        return None;
    }
    let nt = usize::try_from(read_u32(image, E_LFANEW)?).ok()?;
    if read_u32(image, nt)? != NT_SIGNATURE {
        return None;
    }
    let size_offset = nt.checked_add(OPTIONAL_SIZE_FROM_NT)?;
    let size = usize::from(read_u16(image, size_offset)?);
    let start = nt.checked_add(OPTIONAL_FROM_NT)?;
    let end = start.checked_add(size)?;
    let optional = image.get(start..end)?;
    if read_u16(optional, 0)? != OPTIONAL_MAGIC_64 {
        return None;
    }
    Some(optional)
}

/// Reads one data-directory entry from an optional header.
fn directory(optional: &[u8], index: usize) -> Option<(u32, u32)> {
    let count = usize::try_from(read_u32(optional, DIRECTORY_COUNT)?).ok()?;
    if index >= count {
        return None;
    }
    let offset = DATA_DIRECTORY.checked_add(index.checked_mul(DIRECTORY_ENTRY)?)?;
    let address = read_u32(optional, offset)?;
    let size = read_u32(optional, offset.checked_add(4)?)?;
    if address == 0 || size == 0 {
        None
    } else {
        Some((address, size))
    }
}

/// Reads one little-endian `u16` from a checked range.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(value))
}

/// Reads one little-endian `u32` from a checked range.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

/// Reads one little-endian `u64` from a checked range.
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::{certificate_table, mapped_import_slots};

    /// Stores a little-endian `u16` at one offset.
    fn put16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    /// Stores a little-endian `u32` at one offset.
    fn put32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Stores a little-endian `u64` at one offset.
    fn put64(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Creates a small mapped PE image with one import.
    fn image() -> Vec<u8> {
        let mut image = vec![0_u8; 1024];
        put16(&mut image, 0, 0x5a4d);
        put32(&mut image, 60, 0x40);
        put32(&mut image, 0x40, 0x0000_4550);
        put16(&mut image, 0x54, 0x00f0);
        let optional = 0x58;
        put16(&mut image, optional, 0x020b);
        put32(&mut image, optional + 108, 16);
        put32(&mut image, optional + 120, 0x180);
        put32(&mut image, optional + 124, 40);
        put32(&mut image, optional + 144, 0x300);
        put32(&mut image, optional + 148, 16);
        put32(&mut image, 0x180, 0x200);
        put32(&mut image, 0x18c, 1);
        put32(&mut image, 0x190, 0x220);
        put64(&mut image, 0x200, 0x1234);
        put64(&mut image, 0x220, 0xaaaa);
        image[0x300..0x310].copy_from_slice(b"certificate-data");
        image
    }

    #[test]
    fn a_mapped_import_reports_its_slot_and_value() {
        assert_eq!(
            mapped_import_slots(&image(), 0x1000, 256),
            Some(vec![(0x1220, 0xaaaa)])
        );
    }

    #[test]
    fn a_certificate_directory_returns_its_exact_file_range() {
        assert_eq!(
            certificate_table(&image()),
            Some(b"certificate-data".as_slice())
        );
    }

    #[test]
    fn a_certificate_range_past_the_file_reports_none() {
        let mut image = image();
        put32(&mut image, 0x58 + 148, u32::MAX);
        assert!(certificate_table(&image).is_none());
    }

    #[test]
    fn every_short_prefix_returns_without_a_panic() {
        let image = image();
        for end in 0..image.len() {
            let prefix = &image[..end];
            let _ = mapped_import_slots(prefix, 0x1000, 256);
            let _ = certificate_table(prefix);
        }
    }

    #[test]
    fn an_import_walk_respects_its_slot_limit() {
        assert_eq!(mapped_import_slots(&image(), 0x1000, 0), Some(Vec::new()));
    }
}
