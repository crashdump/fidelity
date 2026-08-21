//! The archive boundary.
//!
//! Android reports the signing certificate through `PackageManager`, and that
//! needs a `Context`. The probe cannot reach one without a hidden interface or
//! a new public field, and `docs/plan/06-delivery.md` refuses both. The
//! process maps the archive it runs from. The loaded image that holds Fidelity
//! and that archive share one install root, so this module selects that file
//! and reads the two ranges that hold the signature.
//!
//! The module holds no `unsafe` code, because the kernel answers through the
//! process filesystem and the archive is an ordinary file. It still lives here
//! rather than beside the capability, because `sys` is where this crate
//! touches the operating system.
//!
//! Reading the whole archive is not an option. An application archive reaches
//! tens of megabytes, and `docs/plan/07-state-and-budgets.md` bounds what a
//! scan may cost. The reads below are the tail, then a footer, then the block,
//! and a real archive makes that about 70 KiB.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use fidelity_formats::apk::{signing, zip};
use fidelity_formats::procfs::maps;

/// The mapping table of this process.
const MAPPINGS: &str = "/proc/self/maps";

/// Why the loader cannot name the image that holds Fidelity.
pub(crate) const NO_IMAGE: &str = "the loader names no image that holds Fidelity";

/// Why a process that maps no archive reports no certificate.
pub(crate) const NO_ARCHIVE: &str = "this process maps no application archive";

/// Why an unreadable mapping table reports no certificate.
pub(crate) const NO_MAPPINGS: &str = "the process mapping table could not be read";

/// Why an archive that cannot be opened reports no certificate.
pub(crate) const UNREADABLE: &str = "the application archive could not be read";

/// Why an archive with no directory record reports no certificate.
pub(crate) const NO_DIRECTORY: &str = "the application archive names no central directory";

/// Why an archive with no signing block reports no certificate.
pub(crate) const NO_BLOCK: &str = "the application archive carries no signing block";

/// Why a block that this reader cannot walk reports no certificate.
pub(crate) const NO_CERTIFICATE: &str = "the signing block names no certificate this probe reads";

/// The certificate that signed the archive this process runs from.
///
/// The error names why the certificate is absent, because a probe never
/// reports a failed read as a clean result.
pub(crate) fn signer_certificate() -> Result<Vec<u8>, &'static str> {
    let Some(image) = super::dispatch::image_path() else {
        return Err(NO_IMAGE);
    };
    let Ok(text) = std::fs::read_to_string(MAPPINGS) else {
        return Err(NO_MAPPINGS);
    };
    let Some(path) = maps::package_archive_for_image(&text, &image) else {
        return Err(NO_ARCHIVE);
    };

    let Ok(mut archive) = File::open(path) else {
        return Err(UNREADABLE);
    };
    let Ok(length) = archive.seek(SeekFrom::End(0)) else {
        return Err(UNREADABLE);
    };

    // The directory record sits inside the last 64 KiB and 22 bytes, whatever
    // the size of the archive, because the format writes the comment length as
    // 16 bits.
    let tail_size = length.min(zip::MAX_TAIL as u64);
    let tail = read_at(&mut archive, length - tail_size, tail_size)?;
    let Some(directory) = zip::central_directory_offset(&tail) else {
        return Err(NO_DIRECTORY);
    };

    // The block states its own size in the 24 bytes that end at the directory.
    let Some(footer_at) = directory.checked_sub(24) else {
        return Err(NO_BLOCK);
    };
    let footer = read_at(&mut archive, footer_at, 24)?;
    let Some(size) = signing::block_length(&footer) else {
        return Err(NO_BLOCK);
    };

    let Some(block_at) = directory.checked_sub(size as u64) else {
        return Err(NO_BLOCK);
    };
    let block = read_at(&mut archive, block_at, size as u64)?;
    let Some(certificate) = signing::signer_certificate(&block) else {
        return Err(NO_CERTIFICATE);
    };
    Ok(certificate.to_vec())
}

/// Reads one range of a file, and never more than the reader's own bound.
fn read_at(archive: &mut File, at: u64, size: u64) -> Result<Vec<u8>, &'static str> {
    let Ok(size) = usize::try_from(size) else {
        return Err(UNREADABLE);
    };
    if size > signing::MAX_BLOCK {
        return Err(UNREADABLE);
    }
    if archive.seek(SeekFrom::Start(at)).is_err() {
        return Err(UNREADABLE);
    }

    let mut bytes = vec![0; size];
    if archive.read_exact(&mut bytes).is_err() {
        return Err(UNREADABLE);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{NO_ARCHIVE, signer_certificate};

    #[test]
    fn a_process_that_maps_no_archive_states_that_gap() {
        // A Rust test binary runs from the shell, not from an application, so
        // it maps no archive of its own. That is the negative control a device
        // answers, and the instrumented harness covers the positive one.
        assert_eq!(signer_certificate().err(), Some(NO_ARCHIVE));
    }

    #[test]
    fn the_loader_states_the_image() {
        // The image is what selects one archive out of the many that a real
        // application process maps, so an absent one has to fail closed.
        assert!(super::super::dispatch::image_path().is_some());
    }
}
