//! Safe readers for the loaded ELF structures.

/// The maximum dynamic-array size that the reader accepts.
pub const MAX_DYNAMIC_BYTES: usize = 1024 * 1024;

/// The maximum jump-relocation table size that the reader accepts.
pub const MAX_RELOCATION_BYTES: usize = 4 * 1024 * 1024;

const DYNAMIC_ENTRY_BYTES: usize = 16;
const RELA_ENTRY_BYTES: usize = 24;
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_RELA: u64 = 7;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let field: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(field))
}

fn read_i64(bytes: &[u8], at: usize) -> Option<i64> {
    read_u64(bytes, at).map(|value| i64::from_le_bytes(value.to_le_bytes()))
}

/// The fields that the dynamic array gives to the jump-relocation reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicTable {
    jump_relocations: u64,
    jump_relocation_bytes: u64,
    bound: bool,
}

impl DynamicTable {
    /// The address that the dynamic array gives for the relocation table.
    #[must_use]
    pub const fn jump_relocations(self) -> u64 {
        self.jump_relocations
    }

    /// The size of the relocation table.
    #[must_use]
    pub const fn jump_relocation_bytes(self) -> u64 {
        self.jump_relocation_bytes
    }

    /// Whether the loader binds the table before the image runs.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        self.bound
    }
}

/// The jump-slot relocation offsets that a table holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpSlots {
    offsets: Vec<u64>,
    truncated: bool,
}

impl JumpSlots {
    /// The offsets of the jump slots.
    #[must_use]
    pub fn offsets(&self) -> &[u64] {
        &self.offsets
    }

    /// Whether the table holds more jump slots than the caller accepts.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Reads the jump-relocation fields from an ELF64 dynamic array.
#[must_use]
pub fn dynamic_table(bytes: &[u8]) -> Option<DynamicTable> {
    if bytes.len() > MAX_DYNAMIC_BYTES {
        return None;
    }

    let mut jump_relocations = 0;
    let mut jump_relocation_bytes = 0;
    let mut relocation_form = 0;
    let mut bound = false;

    for at in (0..bytes.len()).step_by(DYNAMIC_ENTRY_BYTES) {
        let tag = read_i64(bytes, at)?;
        let value = read_u64(bytes, at.checked_add(8)?)?;
        match tag {
            DT_NULL => {
                if jump_relocations == 0 || jump_relocation_bytes == 0 || relocation_form != DT_RELA
                {
                    return None;
                }
                return Some(DynamicTable {
                    jump_relocations,
                    jump_relocation_bytes,
                    bound,
                });
            }
            DT_JMPREL => jump_relocations = value,
            DT_PLTRELSZ => jump_relocation_bytes = value,
            DT_PLTREL => relocation_form = value,
            DT_BIND_NOW => bound = true,
            DT_FLAGS if value & DF_BIND_NOW != 0 => bound = true,
            DT_FLAGS_1 if value & DF_1_NOW != 0 => bound = true,
            _ => {}
        }
    }
    None
}

/// Reads ELF64 RELA jump-slot offsets, up to the stated limit.
#[must_use]
pub fn jump_slots(bytes: &[u8], jump_slot: u32, limit: usize) -> Option<JumpSlots> {
    if bytes.len() > MAX_RELOCATION_BYTES || bytes.len() % RELA_ENTRY_BYTES != 0 {
        return None;
    }

    let mut offsets = Vec::with_capacity(limit.min(bytes.len() / RELA_ENTRY_BYTES));
    let mut truncated = false;
    for at in (0..bytes.len()).step_by(RELA_ENTRY_BYTES) {
        let offset = read_u64(bytes, at)?;
        let info = read_u64(bytes, at.checked_add(8)?)?;
        if info & 0xffff_ffff != u64::from(jump_slot) {
            continue;
        }
        if offsets.len() == limit {
            truncated = true;
            continue;
        }
        offsets.push(offset);
    }
    Some(JumpSlots { offsets, truncated })
}

#[cfg(test)]
mod tests {
    use super::{dynamic_table, jump_slots};

    fn dynamic(entries: &[(i64, u64)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (tag, value) in entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn rela(offset: u64, kind: u32) -> Vec<u8> {
        let mut bytes = offset.to_le_bytes().to_vec();
        bytes.extend_from_slice(&u64::from(kind).to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes
    }

    #[test]
    fn a_dynamic_array_reports_the_jump_table() {
        let bytes = dynamic(&[(23, 0x4000), (2, 48), (20, 7), (24, 0), (0, 0)]);
        let Some(table) = dynamic_table(&bytes) else {
            panic!("the dynamic array must answer")
        };
        assert_eq!(
            (table.jump_relocations(), table.jump_relocation_bytes()),
            (0x4000, 48)
        );
        assert!(table.is_bound());
    }

    #[test]
    fn an_array_without_a_terminator_reports_none() {
        assert_eq!(dynamic_table(&dynamic(&[(23, 0x4000)])), None);
    }

    #[test]
    fn the_jump_slot_reader_ignores_other_relocations() {
        let mut bytes = rela(0x1000, 7);
        bytes.extend_from_slice(&rela(0x2000, 6));
        let Some(slots) = jump_slots(&bytes, 7, 8) else {
            panic!("the relocation table must answer")
        };
        assert_eq!(slots.offsets(), &[0x1000]);
    }

    #[test]
    fn the_jump_slot_reader_states_truncation() {
        let mut bytes = Vec::new();
        for index in 0..3 {
            bytes.extend_from_slice(&rela(index * 8, 7));
        }
        let Some(slots) = jump_slots(&bytes, 7, 2) else {
            panic!("the relocation table must answer")
        };
        assert_eq!(slots.offsets().len(), 2);
        assert!(slots.is_truncated());
    }
}
