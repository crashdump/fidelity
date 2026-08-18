//! The reader for an embedded code signature.
//!
//! A code signature is a `SuperBlob`: a header, then one index entry for each
//! slot, then the slots themselves. Every slot is itself a blob that starts
//! with its own magic number and its own length. The reader walks the index
//! and returns the one slot that carries the entitlements.
//!
//! The bytes come from a signed image, and the kernel refuses to run an image
//! whose signature does not match. The reader still treats every field as
//! untrusted, because it reads a length before it reads the bytes that the
//! length describes.

/// The magic number of an embedded code signature.
const SUPERBLOB_MAGIC: u32 = 0xfade_0cc0;

/// The magic number of the entitlements slot.
const ENTITLEMENTS_MAGIC: u32 = 0xfade_7171;

/// The slot that carries the entitlements, as a plist.
const ENTITLEMENTS_SLOT: u32 = 5;

/// The size of a blob header, which is a magic number and a length.
const HEADER: usize = 8;

/// The size of the `SuperBlob` header, which adds the slot count.
const SUPERBLOB_HEADER: usize = 12;

/// The size of one index entry, which is a slot type and an offset.
const INDEX_ENTRY: usize = 8;

/// The largest signature that this reader walks, at 16 MiB.
///
/// A real signature is far smaller. The bound stops a corrupt length from
/// turning into a long walk.
const MAX_SIGNATURE: usize = 16 * 1024 * 1024;

/// Reads one big-endian `u32`, or reports that the bytes are too short.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let field: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(field))
}

/// Reads the entitlements plist out of an embedded code signature.
///
/// Returns `None` when the bytes are not a `SuperBlob`, when no slot carries
/// entitlements, or when any length runs past the end. An image that a build
/// signed without entitlements is the common `None`, and it is not a failure.
///
/// The caller never turns `None` into a clean result. It reports the gap.
#[must_use]
pub fn entitlements(signature: &[u8]) -> Option<&[u8]> {
    if signature.len() > MAX_SIGNATURE || read_u32(signature, 0)? != SUPERBLOB_MAGIC {
        return None;
    }

    // The declared length may be shorter than the bytes that the caller
    // mapped, because the image pads the area that holds the signature. Every
    // later read stays inside the declared length.
    let declared = read_u32(signature, 4)? as usize;
    let signature = signature.get(..declared)?;
    let count = read_u32(signature, 8)? as usize;

    for slot in 0..count {
        let entry = SUPERBLOB_HEADER.checked_add(slot.checked_mul(INDEX_ENTRY)?)?;
        if read_u32(signature, entry)? != ENTITLEMENTS_SLOT {
            continue;
        }

        let at = read_u32(signature, entry.checked_add(4)?)? as usize;
        if read_u32(signature, at)? != ENTITLEMENTS_MAGIC {
            return None;
        }

        // The length covers the header as well as the plist, so a blob that
        // declares less than a header is malformed rather than empty.
        let length = read_u32(signature, at.checked_add(4)?)? as usize;
        let start = at.checked_add(HEADER)?;
        let end = at.checked_add(length)?;
        return signature.get(start..end);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::entitlements;

    /// A real ad-hoc signature that carries a team-prefixed application
    /// identifier. Captured on macOS 26 and ARM64 on 2026-08-10, from a
    /// binary that `codesign --sign - --entitlements` produced. The control
    /// that made it is `tests/platform/controls/entitle.c`.
    const WITH_TEAM: &[u8] = include_bytes!("../fixtures/macho-signature-team.bin");

    /// The same binary, signed ad hoc with no entitlements at all.
    const BARE: &[u8] = include_bytes!("../fixtures/macho-signature-bare.bin");

    /// The entitlements of a fixture, or a failed test.
    fn plist_of(signature: &[u8]) -> &[u8] {
        let Some(plist) = entitlements(signature) else {
            panic!("the fixture carries entitlements")
        };
        plist
    }

    /// One field of a fixture, or a failed test.
    fn field(signature: &[u8], at: usize) -> u32 {
        let Some(value) = super::read_u32(signature, at) else {
            panic!("the fixture holds a field at byte {at}")
        };
        value
    }

    /// Where the index entry for the entitlements slot sits in the fixture.
    ///
    /// The fixture holds five slots, and the entitlements are the third, so a
    /// test that assumed the first would corrupt a slot the reader skips.
    fn entitlements_entry(signature: &[u8]) -> usize {
        let count = field(signature, 8) as usize;
        let found = (0..count)
            .map(|slot| super::SUPERBLOB_HEADER + (slot * super::INDEX_ENTRY))
            .find(|&entry| field(signature, entry) == super::ENTITLEMENTS_SLOT);
        let Some(entry) = found else {
            panic!("the fixture carries an entitlements slot")
        };
        entry
    }

    #[test]
    fn a_signature_with_entitlements_reports_the_plist() {
        assert!(plist_of(WITH_TEAM).starts_with(b"<?xml"));
    }

    #[test]
    fn the_plist_holds_the_identifier_that_the_build_signed() {
        let plist = plist_of(WITH_TEAM);
        let Ok(text) = core::str::from_utf8(plist) else {
            panic!("the fixture holds text")
        };
        assert!(text.contains("ABCDE12345.com.example.app"), "{text}");
    }

    #[test]
    fn a_signature_without_entitlements_reports_none() {
        // The common case, and not a failure. Cargo signs a local build this
        // way, so every test binary in this workspace looks like the fixture.
        assert_eq!(entitlements(BARE), None);
    }

    #[test]
    fn bytes_that_are_not_a_superblob_report_none() {
        assert_eq!(entitlements(b"not a signature at all"), None);
    }

    #[test]
    fn empty_bytes_report_none() {
        assert_eq!(entitlements(&[]), None);
    }

    #[test]
    fn a_truncated_signature_reports_none() {
        // The declared length runs past the bytes that arrived, so every
        // later read has to stay inside the shorter slice.
        assert_eq!(entitlements(&WITH_TEAM[..32]), None);
    }

    #[test]
    fn a_slot_offset_past_the_end_reports_none() {
        let mut broken = WITH_TEAM.to_vec();
        let entry = entitlements_entry(&broken);
        broken[entry + 4..entry + 8].copy_from_slice(&u32::to_be_bytes(0x0fff_ffff));
        assert_eq!(entitlements(&broken), None);
    }

    #[test]
    fn a_slot_count_past_the_end_never_reads_past_the_end() {
        // The bare fixture holds no entitlements slot, so the walk runs to the
        // count. It must stop at the declared length rather than read on.
        let mut broken = BARE.to_vec();
        broken[8..12].copy_from_slice(&u32::to_be_bytes(u32::MAX));
        assert_eq!(entitlements(&broken), None);
    }

    #[test]
    fn an_entitlements_length_past_the_end_reports_none() {
        let mut broken = WITH_TEAM.to_vec();
        let entry = entitlements_entry(&broken);
        let at = field(&broken, entry + 4) as usize;
        assert_eq!(field(&broken, at), super::ENTITLEMENTS_MAGIC);
        broken[at + 4..at + 8].copy_from_slice(&u32::to_be_bytes(u32::MAX));
        assert_eq!(entitlements(&broken), None);
    }

    #[test]
    fn a_slot_that_is_not_an_entitlements_blob_reports_none() {
        // The index says entitlements and the blob says something else. That
        // is a malformed signature, and it must never read as absent data.
        let mut broken = WITH_TEAM.to_vec();
        let entry = entitlements_entry(&broken);
        let at = field(&broken, entry + 4) as usize;
        broken[at..at + 4].copy_from_slice(&u32::to_be_bytes(0xdead_beef));
        assert_eq!(entitlements(&broken), None);
    }
}
