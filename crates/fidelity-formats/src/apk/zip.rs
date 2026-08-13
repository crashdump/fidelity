//! The reader for the archive directory that names where the signature sits.
//!
//! An archive ends with an "end of central directory" record, and that record
//! holds the offset of the central directory. The signing block sits directly
//! before that offset, so finding the record is how a reader finds the
//! signature without reading the whole archive.
//!
//! Reading the whole archive is not an option. An application archive reaches
//! tens of megabytes, and `docs/plan/07-state-and-budgets.md` bounds what a
//! scan may cost. The caller therefore reads the tail, calls this module, then
//! reads the one range that the answer names.

/// The magic number of the end-of-central-directory record.
const END_MAGIC: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

/// The size of that record, without the comment that may follow it.
const END_SIZE: usize = 22;

/// Where the central-directory offset sits inside the record.
const OFFSET_FIELD: usize = 16;

/// Where the comment length sits inside the record.
const COMMENT_FIELD: usize = 20;

/// The longest comment that an archive may carry, which bounds the search.
///
/// The format writes the comment length as 16 bits, so the record sits inside
/// the last 64 KiB and 22 bytes of the file. A caller that reads that much
/// always finds it.
pub const MAX_COMMENT: usize = 0xffff;

/// The most that a caller ever needs to read from the end of an archive.
pub const MAX_TAIL: usize = MAX_COMMENT + END_SIZE;

/// Reads one little-endian `u32`, or reports that the bytes are too short.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let field: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

/// Reads one little-endian `u16`, or reports that the bytes are too short.
fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let field: [u8; 2] = bytes.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(field))
}

/// Where the central directory starts, read from the tail of an archive.
///
/// `tail` is the last [`MAX_TAIL`] bytes of the file, or the whole file when
/// it is shorter. The answer is an offset from the start of the file, so the
/// caller adds nothing to it.
///
/// Returns `None` when the tail holds no record. The caller reports that gap,
/// and it never reads a `None` as a clean result.
///
/// The search runs backwards, because a comment may hold bytes that look like
/// the record. The magic number alone does not select one: a repackager can
/// write a decoy record inside the comment on purpose. A record counts only
/// when the comment length it states reaches the end of the file, which is the
/// same rule that Android applies. A reader that takes the last magic number
/// instead can read a decoy that Android rejects, and it then reads the
/// signature from wherever that decoy points.
#[must_use]
pub fn central_directory_offset(tail: &[u8]) -> Option<u64> {
    let last = tail.len().checked_sub(END_SIZE)?;

    for at in (0..=last).rev() {
        if tail.get(at..at.checked_add(4)?) != Some(&END_MAGIC) {
            continue;
        }
        let Some(comment) = read_u16(tail, at.checked_add(COMMENT_FIELD)?) else {
            continue;
        };
        let Some(ends) = at
            .checked_add(END_SIZE)
            .and_then(|after| after.checked_add(usize::from(comment)))
        else {
            continue;
        };
        if ends != tail.len() {
            continue;
        }
        let offset = read_u32(tail, at.checked_add(OFFSET_FIELD)?)?;
        return Some(u64::from(offset));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        COMMENT_FIELD, END_MAGIC, END_SIZE, MAX_TAIL, OFFSET_FIELD, central_directory_offset,
    };

    /// A real archive that `apksigner` signed, recorded on 2026-08-10. The
    /// control that made it is `evidence/controls/make-apk.sh`.
    const SIGNED: &[u8] = include_bytes!("../fixtures/apk-signed-v2v3.apk");

    #[test]
    fn the_recorded_archive_names_its_central_directory() {
        assert_eq!(central_directory_offset(SIGNED), Some(8192));
    }

    #[test]
    fn a_tail_that_is_shorter_than_the_file_still_answers() {
        // The caller reads the tail, not the file, so this is the real shape.
        let tail = &SIGNED[SIGNED.len() - 512..];
        assert_eq!(central_directory_offset(tail), Some(8192));
    }

    #[test]
    fn the_search_runs_backwards_past_a_comment_that_looks_like_the_record() {
        // A comment may hold the magic number. The record that ends the file
        // is the real one, so a forward search would read the decoy.
        let mut archive = SIGNED.to_vec();
        let decoy = [
            0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0,
            0,
        ];
        archive.splice(0..0, decoy);
        assert_eq!(central_directory_offset(&archive), Some(8192));
    }

    #[test]
    fn a_decoy_that_android_refuses_never_wins() {
        // A repackager writes a second record inside the comment of the real
        // one. Android reads the comment length and refuses a record that does
        // not reach the end of the file, so this reader refuses it too. A
        // reader that takes the last magic number reads the decoy instead, and
        // the decoy names a signing block that the attacker wrote.
        let mut archive = SIGNED.to_vec();
        let Some(real) = archive.len().checked_sub(END_SIZE) else {
            panic!("the fixture is shorter than one record");
        };
        assert_eq!(
            archive.get(real..real + 4),
            Some(&END_MAGIC[..]),
            "the fixture must end with its record and carry no comment"
        );

        // The real record states a comment that holds the decoy and 8 bytes
        // after it, so the decoy cannot reach the end of the file.
        let comment: u16 = 30;
        assert_eq!(usize::from(comment), END_SIZE + 8);
        archive[real + COMMENT_FIELD..real + COMMENT_FIELD + 2]
            .copy_from_slice(&comment.to_le_bytes());

        let mut decoy = [0_u8; END_SIZE];
        decoy[..4].copy_from_slice(&END_MAGIC);
        decoy[OFFSET_FIELD..OFFSET_FIELD + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&decoy);
        archive.extend_from_slice(&[0; 8]);

        assert_eq!(central_directory_offset(&archive), Some(8192));
    }

    #[test]
    fn bytes_with_no_record_report_none() {
        assert_eq!(central_directory_offset(b"not an archive at all"), None);
    }

    #[test]
    fn empty_bytes_report_none() {
        assert_eq!(central_directory_offset(&[]), None);
    }

    #[test]
    fn a_truncated_record_reports_none() {
        // The magic number arrived and the offset field did not.
        assert_eq!(central_directory_offset(&super::END_MAGIC), None);
    }

    #[test]
    fn the_tail_bound_covers_the_longest_comment() {
        // The format writes the comment length as 16 bits, so a caller that
        // reads this much always reaches the record.
        assert_eq!(MAX_TAIL, 0xffff + 22);
    }
}
