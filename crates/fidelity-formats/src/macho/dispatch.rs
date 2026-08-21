//! The safe reader for Mach-O dispatch sections.

/// The maximum load-command size that the reader accepts.
pub const MAX_COMMAND_BYTES: usize = 4 * 1024 * 1024;

const MAX_POINTER_SECTIONS: usize = 128;
const LOAD_COMMAND_BYTES: usize = 8;
const SEGMENT_COMMAND_BYTES: usize = 72;
const SECTION_BYTES: usize = 80;
const LC_SEGMENT_64: u32 = 0x19;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const SECTION_TYPE: u32 = 0xff;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;

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

/// One symbol-pointer section of the loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerSection {
    address: u64,
    bytes: u64,
}

impl PointerSection {
    /// The unslid address of the section.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    /// The size of the section.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// The dispatch layout that the load commands describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchLayout {
    sections: Vec<PointerSection>,
    bound: bool,
}

impl DispatchLayout {
    /// The symbol-pointer sections.
    #[must_use]
    pub fn sections(&self) -> &[PointerSection] {
        &self.sections
    }

    /// Whether chained fixups bind the image before it runs.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.bound
    }
}

/// Reads the symbol-pointer sections from bounded Mach-O load commands.
#[must_use]
pub fn dispatch_layout(commands: &[u8], command_count: u32) -> Option<DispatchLayout> {
    if commands.len() > MAX_COMMAND_BYTES {
        return None;
    }

    let mut at = 0;
    let mut bound = false;
    let mut sections = Vec::new();
    for _ in 0..command_count {
        let kind = read_u32(commands, at)?;
        let size = usize::try_from(read_u32(commands, at.checked_add(4)?)?).ok()?;
        if size < LOAD_COMMAND_BYTES {
            return None;
        }
        let end = at.checked_add(size)?;
        commands.get(at..end)?;

        if kind == LC_DYLD_CHAINED_FIXUPS {
            bound = true;
        }
        if kind == LC_SEGMENT_64 {
            if size < SEGMENT_COMMAND_BYTES {
                return None;
            }
            let count = usize::try_from(read_u32(commands, at.checked_add(64)?)?).ok()?;
            let section_bytes = count.checked_mul(SECTION_BYTES)?;
            let required = SEGMENT_COMMAND_BYTES.checked_add(section_bytes)?;
            if required > size {
                return None;
            }
            for index in 0..count {
                let section = at
                    .checked_add(SEGMENT_COMMAND_BYTES)?
                    .checked_add(index.checked_mul(SECTION_BYTES)?)?;
                let flags = read_u32(commands, section.checked_add(64)?)?;
                if flags & SECTION_TYPE != S_NON_LAZY_SYMBOL_POINTERS {
                    continue;
                }
                if sections.len() == MAX_POINTER_SECTIONS {
                    return None;
                }
                sections.push(PointerSection {
                    address: read_u64(commands, section.checked_add(32)?)?,
                    bytes: read_u64(commands, section.checked_add(40)?)?,
                });
            }
        }
        at = end;
    }

    if at != commands.len() {
        return None;
    }
    Some(DispatchLayout { sections, bound })
}

#[cfg(test)]
mod tests {
    use super::dispatch_layout;

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;

    fn command(kind: u32) -> Vec<u8> {
        let mut bytes = kind.to_le_bytes().to_vec();
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        bytes
    }

    fn segment(address: u64, size: u64) -> Vec<u8> {
        let mut bytes = vec![0; 72 + 80];
        let Ok(length) = u32::try_from(bytes.len()) else {
            panic!("the test command must fit in one field")
        };
        bytes[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[72 + 32..72 + 40].copy_from_slice(&address.to_le_bytes());
        bytes[72 + 40..72 + 48].copy_from_slice(&size.to_le_bytes());
        bytes[72 + 64..72 + 68].copy_from_slice(&S_NON_LAZY_SYMBOL_POINTERS.to_le_bytes());
        bytes
    }

    #[test]
    fn chained_commands_report_the_pointer_section() {
        let mut bytes = command(LC_DYLD_CHAINED_FIXUPS);
        bytes.extend_from_slice(&segment(0x4000, 24));
        let Some(layout) = dispatch_layout(&bytes, 2) else {
            panic!("the load commands must answer")
        };
        assert!(layout.is_bound());
        assert_eq!(layout.sections()[0].address(), 0x4000);
        assert_eq!(layout.sections()[0].bytes(), 24);
    }

    #[test]
    fn a_zero_command_size_reports_none() {
        assert_eq!(dispatch_layout(&[0; 8], 1), None);
    }

    #[test]
    fn a_section_count_that_passes_the_command_reports_none() {
        let mut bytes = segment(0x4000, 8);
        bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(dispatch_layout(&bytes, 1), None);
    }
}
