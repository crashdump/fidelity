//! The reader for the System Information structure.
//!
//! A raw SMBIOS table is a sequence of structures. Each one starts with a type,
//! a length, and a handle, and the length covers the formatted area only. The
//! text that the structure names follows it, as a run of strings that each end
//! with a zero byte, and a second zero byte ends the run. A field holds the
//! number of the string it wants, and zero means that the firmware stated none.
//!
//! One structure states the identity of the machine, and this reader returns
//! the two fields of it that [`vendor`](super::vendor) judges. It reads no
//! serial number and no identifier, so it carries nothing that names the person
//! who owns the machine.

/// The structure that states the identity of the machine.
const SYSTEM_INFORMATION: u8 = 1;

/// The structure that ends the table.
const END_OF_TABLE: u8 = 127;

/// The header of every structure: a type, a length, and a handle.
const HEADER_BYTES: usize = 4;

/// Where the System Information structure numbers its manufacturer.
const MANUFACTURER: usize = 4;

/// Where it numbers its product.
const PRODUCT: usize = 5;

/// What the firmware states about the machine that runs this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemInformation<'a> {
    /// Who the firmware names as the maker.
    pub manufacturer: &'a str,

    /// What the firmware names as the product.
    pub product: &'a str,
}

/// Reads the System Information strings out of a raw SMBIOS table.
///
/// `table` is the structure area alone. On Windows that is the
/// `SMBIOSTableData` field, which starts 8 bytes into what
/// `GetSystemFirmwareTable` returns.
///
/// Returns `None` when the table holds no such structure, and when a length or
/// a string run runs past the end of the bytes. The caller reports that as a
/// gap, because a table that this reader cannot walk states nothing about the
/// machine either way.
#[must_use]
pub fn system_information(table: &[u8]) -> Option<SystemInformation<'_>> {
    let mut cursor = 0;

    loop {
        let header = table.get(cursor..cursor + HEADER_BYTES)?;
        let kind = header[0];
        // The length covers the header too, so a value below it names a
        // structure smaller than the bytes already read. That table is
        // malformed, and it states nothing about the machine either way.
        let formatted = usize::from(header[1]);
        if kind == END_OF_TABLE || formatted < HEADER_BYTES {
            return None;
        }

        // The strings sit after the formatted area, and two zero bytes end
        // them. A structure that names no string still writes both, so the run
        // is never empty.
        let start = cursor.checked_add(formatted)?;
        let end = run_end(table, start)?;

        if kind == SYSTEM_INFORMATION {
            let fields = table.get(cursor..start)?;
            let strings = table.get(start..end - 2)?;
            return Some(SystemInformation {
                manufacturer: string(strings, *fields.get(MANUFACTURER)?)?,
                product: string(strings, *fields.get(PRODUCT)?)?,
            });
        }

        cursor = end;
    }
}

/// Finds where the run of strings ends, and returns the byte after it.
///
/// The two zero bytes that end the run belong to the answer, so the caller
/// steps to the next structure with it and drops them for the text.
fn run_end(table: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    loop {
        if table.get(cursor..cursor + 2)? == [0, 0] {
            return Some(cursor + 2);
        }
        cursor += 1;
    }
}

/// Takes one string out of the run by the number that a field holds.
///
/// Zero means that the firmware stated none, and that reads as empty text
/// rather than as a failure. Every other number counts from one.
fn string(strings: &[u8], number: u8) -> Option<&str> {
    if number == 0 {
        return Some("");
    }
    let index = usize::from(number).checked_sub(1)?;
    let bytes = strings.split(|byte| *byte == 0).nth(index)?;
    // A firmware that writes text this reader cannot decode states nothing
    // about the machine, so the caller reports a gap rather than a guess.
    core::str::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::{SystemInformation, system_information};

    /// A real SMBIOS table, captured on 2026-08-18 from the Windows guest that
    /// `tests/platform/vm/windows/` builds. QEMU 11.0 runs it, and EDK II
    /// supplies the firmware.
    ///
    /// The capture states no serial number and a zero identifier, so it names
    /// no machine that a person owns.
    const QEMU: &[u8] = include_bytes!("../fixtures/smbios-qemu.bin");

    #[test]
    fn the_reader_takes_the_identity_of_the_machine() {
        assert_eq!(
            system_information(QEMU),
            Some(SystemInformation {
                manufacturer: "QEMU",
                product: "QEMU Virtual Machine",
            })
        );
    }

    #[test]
    fn the_reader_walks_past_a_structure_it_does_not_want() {
        // The captured table states the BIOS last and the identity first, so
        // this proves the walk on a table that states them the other way. A
        // reader that assumed an order would read the wrong structure, and the
        // specification fixes no order.
        let mut table = vec![
            // A BIOS Information structure, which names two strings.
            0, 4, 0, 0, b'E', b'D', b'K', 0, b'1', 0, 0,
        ];
        table.extend_from_slice(QEMU);
        assert_eq!(
            system_information(&table),
            Some(SystemInformation {
                manufacturer: "QEMU",
                product: "QEMU Virtual Machine",
            })
        );
    }

    #[test]
    fn a_field_that_names_no_string_reads_as_empty_text() {
        // Zero is what the specification states for a field that the firmware
        // left out, so it is not a failure.
        let table = [1, 6, 0, 0, 0, 1, b'A', b'C', b'M', b'E', 0, 0];
        assert_eq!(
            system_information(&table),
            Some(SystemInformation {
                manufacturer: "",
                product: "ACME",
            })
        );
    }

    #[test]
    fn a_table_with_no_identity_reads_as_no_answer() {
        // Only the end marker. Nothing states the machine, so the caller
        // reports a gap.
        assert_eq!(system_information(&[127, 4, 0, 0, 0, 0]), None);
    }

    #[test]
    fn empty_bytes_read_as_no_answer() {
        assert_eq!(system_information(&[]), None);
    }

    #[test]
    fn a_length_that_runs_past_the_end_reads_as_no_answer() {
        // The one shape that a malformed table takes, and the reader must stop
        // rather than read what follows it in memory.
        assert_eq!(system_information(&[1, 200, 0, 0, b'A', 0, 0]), None);
    }

    #[test]
    fn a_length_below_the_header_reads_as_no_answer() {
        // The length covers the header as well, so a value below it states a
        // structure smaller than the four bytes already read. The table is
        // malformed, and a malformed table states nothing about the machine.
        assert_eq!(system_information(&[1, 2, 0, 0, 0, 0]), None);
    }

    #[test]
    fn a_run_of_strings_that_never_ends_reads_as_no_answer() {
        assert_eq!(system_information(&[1, 6, 0, 0, 1, 1, b'A', b'B']), None);
    }

    #[test]
    fn a_field_that_names_a_string_the_run_lacks_reads_as_no_answer() {
        assert_eq!(system_information(&[1, 6, 0, 0, 9, 1, b'A', 0, 0]), None);
    }
}
