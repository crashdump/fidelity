//! The reader for the signing block of an Android archive.
//!
//! The block sits directly before the central directory. It holds its own size
//! twice, a magic string, and a sequence of identifier-value pairs. One pair
//! carries the signature scheme, and inside it the certificate that signed the
//! archive.
//!
//! The reader returns that certificate and stops. Android compares a SHA-256
//! of it, and `docs/plan/04-detectors-and-platforms.md` states that, but this
//! crate depends on nothing and holds no hash. The capability hashes what this
//! returns.
//!
//! A newer scheme answers first, so the order is v3.1, then v3, then v2. An
//! archive that rotated its key holds the current signer in v3.1 and the old
//! one in v3, and every system above the v1 floor reads v3.1.

/// The magic string that ends the block.
const MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// The size of the trailing size field and the magic string together.
const FOOTER: usize = 24;

/// The identifier of the scheme v2 block.
const SCHEME_V2: u32 = 0x7109_871a;

/// The identifier of the scheme v3 block.
const SCHEME_V3: u32 = 0xf053_68c0;

/// The identifier of the scheme v3.1 block.
///
/// Checked against `V3SchemeConstants.java` in the AOSP `apksig` tool on
/// 2026-08-13.
const SCHEME_V31: u32 = 0x1b93_ad61;

// Android 13, which is API 33, is the first system that reads a v3.1 block,
// and `MIN_SDK_WITH_V31_SUPPORT` in the same file states that. The v1 floor in
// `docs/plan/04-detectors-and-platforms.md` is API 34, so every system that
// runs this reader reads that block, and the preference below needs no test
// against the running SDK.

/// The largest block that this reader walks, at 4 MiB.
///
/// A real block holds a few kilobytes for each signer. The bound stops a
/// corrupt size from turning into a long walk.
pub const MAX_BLOCK: usize = 4 * 1024 * 1024;

/// Reads one little-endian `u32`, or reports that the bytes are too short.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let field: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

/// Reads one little-endian `u64`, or reports that the bytes are too short.
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let field: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(field))
}

/// How many bytes before the central directory the signing block occupies.
///
/// `footer` is the 24 bytes that sit directly before the central directory.
/// The answer counts from the start of the block to the central directory, so
/// a caller reads that many bytes ending there.
///
/// Returns `None` when those bytes are not a block footer.
#[must_use]
pub fn block_length(footer: &[u8]) -> Option<usize> {
    let at = footer.len().checked_sub(FOOTER)?;
    if footer.get(at.checked_add(8)?..) != Some(MAGIC.as_slice()) {
        return None;
    }

    // The size field counts every byte after itself, so the block adds the
    // eight bytes of the leading copy of the same number.
    let size = usize::try_from(read_u64(footer, at)?).ok()?;
    if size > MAX_BLOCK {
        return None;
    }
    size.checked_add(8)
}

/// Reads the certificate that signed the archive.
///
/// `block` is the whole signing block, which [`block_length`] measures. The
/// answer is one X.509 certificate, in the form that the archive stores it.
///
/// Returns `None` when the block holds no scheme that this reader knows, when
/// a length runs past the end, or when the two copies of the block size
/// disagree. Each one states that the bytes are not a block this reader can
/// trust, and the caller reports that gap rather than a clean result.
#[must_use]
pub fn signer_certificate(block: &[u8]) -> Option<&[u8]> {
    if block.len() > MAX_BLOCK {
        return None;
    }

    // The size sits at both ends, and the format states that the two agree. A
    // disagreement means the caller read the wrong range.
    let trailing = block.len().checked_sub(FOOTER)?;
    if read_u64(block, 0)? != read_u64(block, trailing)? {
        return None;
    }

    // The walk reads every scheme it knows, because a block appears in any
    // order and the newest one wins whatever that order is.
    let mut v31 = None;
    let mut v3 = None;
    let mut v2 = None;
    let mut at = 8;

    while at < trailing {
        let length = usize::try_from(read_u64(block, at)?).ok()?;
        let identifier = read_u32(block, at.checked_add(8)?)?;
        let start = at.checked_add(12)?;
        let end = at.checked_add(8)?.checked_add(length)?;
        let value = block.get(start..end)?;

        match identifier {
            SCHEME_V31 if v31.is_none() => v31 = certificate(value),
            SCHEME_V3 if v3.is_none() => v3 = certificate(value),
            SCHEME_V2 if v2.is_none() => v2 = certificate(value),
            _ => {}
        }

        at = end;
    }

    // An archive that rotated its key carries the current signer in v3.1 and
    // the signer it rotated away from in v3. Every supported system reads
    // v3.1, so this reader prefers it. A reader that took v3 instead would
    // report the old certificate, and a valid release would look repackaged.
    v31.or(v3).or(v2)
}

/// Takes the first certificate out of one scheme block.
///
/// The shape is the same for v2 and for v3: a sequence of signers, then one
/// signer's signed data, then the digests, then the certificates.
fn certificate(scheme: &[u8]) -> Option<&[u8]> {
    let signers = first(scheme)?;
    let signer = first(signers)?;
    let signed_data = first(signer)?;

    // The signed data holds the digests first and the certificates second, so
    // the reader steps over one element to reach them.
    let digests = element(signed_data, 0)?;
    let after = 4usize.checked_add(digests.len())?;
    let certificates = element(signed_data, after)?;

    first(certificates)
}

/// The first length-prefixed element of a sequence.
fn first(bytes: &[u8]) -> Option<&[u8]> {
    element(bytes, 0)
}

/// One length-prefixed element, at a stated offset.
///
/// Every sequence in this format writes a 32-bit length and then that many
/// bytes, so one helper reads every level.
fn element(bytes: &[u8], at: usize) -> Option<&[u8]> {
    let length = usize::try_from(read_u32(bytes, at)?).ok()?;
    let start = at.checked_add(4)?;
    let end = start.checked_add(length)?;
    bytes.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::{
        FOOTER, MAGIC, SCHEME_V2, SCHEME_V3, SCHEME_V31, block_length, signer_certificate,
    };
    use crate::apk::zip::central_directory_offset;

    /// A real archive that `apksigner` signed with both schemes, recorded on
    /// 2026-08-10. `evidence/controls/make-apk.sh` builds it.
    const SIGNED: &[u8] = include_bytes!("../fixtures/apk-signed-v2v3.apk");

    /// The signing block of the recorded archive.
    fn block() -> &'static [u8] {
        let Some(directory) = central_directory_offset(SIGNED) else {
            panic!("the fixture names its central directory")
        };
        let Ok(directory) = usize::try_from(directory) else {
            panic!("the fixture is smaller than one address")
        };
        let Some(length) = block_length(&SIGNED[..directory]) else {
            panic!("the fixture carries a signing block")
        };
        &SIGNED[directory - length..directory]
    }

    /// The certificate that the recorded archive carries.
    ///
    /// Two independent sources agree on its digest, and
    /// `evidence/controls/make-apk.sh` prints both: `keytool -list -v` on the
    /// keystore, and a walk of the block.
    fn recorded() -> &'static [u8] {
        let Some(certificate) = signer_certificate(block()) else {
            panic!("the fixture carries a certificate")
        };
        certificate
    }

    #[test]
    fn the_recorded_archive_states_its_block_length() {
        // Measured with an independent walk on 2026-08-10: 4088 bytes after
        // the leading size field, and 4096 with it.
        assert_eq!(block().len(), 4096);
    }

    #[test]
    fn the_recorded_archive_reports_a_certificate() {
        // An X.509 certificate is a DER sequence, so it starts with 0x30.
        assert_eq!(recorded().first(), Some(&0x30));
    }

    #[test]
    fn the_certificate_is_the_one_that_signed_the_archive() {
        // This crate holds no hash, so the test names the certificate by its
        // subject instead, and the probe proves the digest. Measured on
        // 2026-08-10: 783 bytes, and both schemes carry the same one.
        let certificate = recorded();
        assert_eq!(certificate.len(), 783);
        assert!(
            certificate
                .windows(13)
                .any(|window| window == b"fidelity test"),
            "the recorded certificate names its subject"
        );
    }

    /// One length-prefixed element, which is how every level of the format
    /// writes a value.
    fn elem(payload: &[u8]) -> Vec<u8> {
        let Ok(length) = u32::try_from(payload.len()) else {
            panic!("a test value is never that long")
        };
        let mut out = length.to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// A scheme block that carries one certificate.
    ///
    /// The nesting is the one that the reader walks: a sequence of signers, a
    /// signer, its signed data, then the digests and the certificates.
    fn scheme(certificate: &[u8]) -> Vec<u8> {
        let mut signed_data = elem(b"digests");
        signed_data.extend_from_slice(&elem(&elem(certificate)));
        elem(&elem(&elem(&signed_data)))
    }

    /// A signing block that holds the stated identifier and value pairs.
    fn signing_block(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (identifier, value) in entries {
            let Ok(length) = u64::try_from(value.len() + 4) else {
                panic!("a test value is never that long")
            };
            body.extend_from_slice(&length.to_le_bytes());
            body.extend_from_slice(&identifier.to_le_bytes());
            body.extend_from_slice(value);
        }

        let Ok(size) = u64::try_from(body.len() + FOOTER) else {
            panic!("a test block is never that long")
        };
        let mut block = size.to_le_bytes().to_vec();
        block.extend_from_slice(&body);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(MAGIC);
        block
    }

    #[test]
    fn a_rotated_archive_reports_the_signer_that_android_selects() {
        // An archive that rotated its key carries the current signer in v3.1
        // and the signer it rotated away from in v3. Every supported system
        // reads v3.1, so a reader that took v3 would report the old
        // certificate and a valid release would look repackaged. The v3 block
        // is written last on purpose, because the answer must not depend on
        // the order.
        let block = signing_block(&[
            (SCHEME_V31, scheme(b"the current certificate")),
            (SCHEME_V2, scheme(b"the v2 certificate")),
            (SCHEME_V3, scheme(b"the rotated away certificate")),
        ]);
        assert_eq!(
            signer_certificate(&block),
            Some(b"the current certificate".as_slice())
        );
    }

    #[test]
    fn an_archive_with_no_rotation_still_reports_its_v3_signer() {
        // The common case keeps working: no v3.1 block, so v3 answers.
        let block = signing_block(&[
            (SCHEME_V2, scheme(b"the v2 certificate")),
            (SCHEME_V3, scheme(b"the v3 certificate")),
        ]);
        assert_eq!(
            signer_certificate(&block),
            Some(b"the v3 certificate".as_slice())
        );
    }

    #[test]
    fn a_block_whose_two_sizes_disagree_reports_none() {
        // The pair is what tells a caller that it read the right range, so a
        // disagreement must never produce a certificate.
        let mut broken = block().to_vec();
        broken[0] ^= 0xff;
        assert_eq!(signer_certificate(&broken), None);
    }

    #[test]
    fn a_footer_that_is_not_a_block_reports_none() {
        assert_eq!(block_length(b"not a signing block at all"), None);
    }

    #[test]
    fn a_short_footer_reports_none() {
        assert_eq!(block_length(&[0; 8]), None);
    }

    #[test]
    fn the_two_schemes_carry_the_same_certificate_in_this_archive() {
        // The reader prefers v3, because that block carries a rotated key and
        // v2 would report the key that an application rotated away from. The
        // recorded archive rotated nothing, so the two agree, and that is what
        // makes the preference safe to assert here.
        let Some(found) = signer_certificate(block()) else {
            panic!("the fixture carries a certificate")
        };
        assert_eq!(found, recorded());
    }

    #[test]
    fn bytes_that_are_not_a_block_report_none() {
        assert_eq!(signer_certificate(b"not a signing block at all"), None);
    }

    #[test]
    fn empty_bytes_report_none() {
        assert_eq!(signer_certificate(&[]), None);
    }
}
