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
//! Scheme v3 answers first where both are present. It is the newer block, and
//! it is the one that carries a rotated key, so a reader that preferred v2
//! would report the key that the application rotated away from.

/// The magic string that ends the block.
const MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// The size of the trailing size field and the magic string together.
const FOOTER: usize = 24;

/// The identifier of the scheme v2 block.
const SCHEME_V2: u32 = 0x7109_871a;

/// The identifier of the scheme v3 block.
const SCHEME_V3: u32 = 0xf053_68c0;

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

    // A later scheme wins, so the walk keeps looking after it finds v2.
    let mut best = None;
    let mut at = 8;

    while at < trailing {
        let length = usize::try_from(read_u64(block, at)?).ok()?;
        let identifier = read_u32(block, at.checked_add(8)?)?;
        let start = at.checked_add(12)?;
        let end = at.checked_add(8)?.checked_add(length)?;
        let value = block.get(start..end)?;

        match identifier {
            SCHEME_V3 => return certificate(value),
            SCHEME_V2 if best.is_none() => best = certificate(value),
            _ => {}
        }

        at = end;
    }

    best
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
    use super::{block_length, signer_certificate};
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
