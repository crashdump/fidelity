//! The safe reader for a Mach-O code-signature location.

use super::dispatch::MAX_COMMAND_BYTES;

const LOAD_COMMAND_BYTES: usize = 8;
const SEGMENT_COMMAND_BYTES: usize = 72;
const SIGNATURE_COMMAND_BYTES: usize = 16;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LINKEDIT: &[u8] = b"__LINKEDIT";
const MAX_SIGNATURE_BYTES: u32 = 16 * 1024 * 1024;

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let field: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let field: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(field))
}

/// The mapped code-signature range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureLayout {
    address: u64,
    bytes: usize,
}

impl SignatureLayout {
    /// The address of the first signature byte.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    /// The size of the signature.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
}

/// Reads one code-signature range from bounded Mach-O load commands.
#[must_use]
pub fn signature_layout(
    commands: &[u8],
    command_count: u32,
    slide: i64,
) -> Option<SignatureLayout> {
    if commands.len() > MAX_COMMAND_BYTES {
        return None;
    }

    let mut at = 0;
    let mut linkedit = None;
    let mut signature = None;
    for _ in 0..command_count {
        let kind = read_u32(commands, at)?;
        let size = usize::try_from(read_u32(commands, at.checked_add(4)?)?).ok()?;
        if size < LOAD_COMMAND_BYTES {
            return None;
        }
        let end = at.checked_add(size)?;
        commands.get(at..end)?;

        match kind {
            LC_SEGMENT_64 if size >= SEGMENT_COMMAND_BYTES => {
                let name = commands.get(at.checked_add(8)?..at.checked_add(24)?)?;
                if name.starts_with(LINKEDIT) && name.get(LINKEDIT.len()) == Some(&0) {
                    if linkedit.is_some() {
                        return None;
                    }
                    linkedit = Some((
                        read_u64(commands, at.checked_add(24)?)?,
                        read_u64(commands, at.checked_add(40)?)?,
                        read_u64(commands, at.checked_add(48)?)?,
                    ));
                }
            }
            LC_CODE_SIGNATURE if size >= SIGNATURE_COMMAND_BYTES => {
                if signature.is_some() {
                    return None;
                }
                signature = Some((
                    read_u32(commands, at.checked_add(8)?)?,
                    read_u32(commands, at.checked_add(12)?)?,
                ));
            }
            LC_SEGMENT_64 | LC_CODE_SIGNATURE => return None,
            _ => {}
        }
        at = end;
    }

    if at != commands.len() {
        return None;
    }
    fit(linkedit?, signature?, slide)
}

fn fit(
    (vmaddr, fileoff, filesize): (u64, u64, u64),
    (dataoff, datasize): (u32, u32),
    slide: i64,
) -> Option<SignatureLayout> {
    if datasize == 0 || datasize > MAX_SIGNATURE_BYTES {
        return None;
    }
    let start = u64::from(dataoff);
    let end = start.checked_add(u64::from(datasize))?;
    if start < fileoff || end > fileoff.checked_add(filesize)? {
        return None;
    }
    let address = vmaddr
        .checked_sub(fileoff)?
        .checked_add(start)?
        .checked_add_signed(slide)?;
    Some(SignatureLayout {
        address,
        bytes: datasize as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::signature_layout;

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1d;

    fn linkedit(vmaddr: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        let mut bytes = vec![0; 72];
        bytes[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        bytes[4..8].copy_from_slice(&72_u32.to_le_bytes());
        bytes[8..19].copy_from_slice(b"__LINKEDIT\0");
        bytes[24..32].copy_from_slice(&vmaddr.to_le_bytes());
        bytes[40..48].copy_from_slice(&fileoff.to_le_bytes());
        bytes[48..56].copy_from_slice(&filesize.to_le_bytes());
        bytes
    }

    fn signature(dataoff: u32, datasize: u32) -> Vec<u8> {
        let mut bytes = Vec::from(LC_CODE_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&16_u32.to_le_bytes());
        bytes.extend_from_slice(&dataoff.to_le_bytes());
        bytes.extend_from_slice(&datasize.to_le_bytes());
        bytes
    }

    #[test]
    fn a_signature_inside_linkedit_reports_its_mapped_range() {
        let mut commands = linkedit(0x0010_0000, 0x1000, 0x0001_0000);
        commands.extend_from_slice(&signature(0x2000, 0x300));
        let Some(layout) = signature_layout(&commands, 2, 0x4000) else {
            panic!("the valid signature layout must answer")
        };
        assert_eq!(layout.address(), 0x0010_5000);
        assert_eq!(layout.bytes(), 0x300);
    }

    #[test]
    fn a_signature_outside_linkedit_reports_none() {
        let mut commands = linkedit(0x0010_0000, 0x1000, 0x1000);
        commands.extend_from_slice(&signature(0x3000, 0x300));
        assert_eq!(signature_layout(&commands, 2, 0), None);
    }

    #[test]
    fn a_command_that_passes_the_slice_reports_none() {
        let mut commands = linkedit(0x0010_0000, 0x1000, 0x0001_0000);
        commands[4..8].copy_from_slice(&80_u32.to_le_bytes());
        assert_eq!(signature_layout(&commands, 1, 0), None);
    }
}
