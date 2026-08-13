//! The fs-verity boundary.
//!
//! fs-verity is the one thing a Linux kernel offers that answers the
//! platform-trust question. The kernel holds a Merkle tree over the file and
//! it refuses a page that no longer matches, so a file with verity enabled
//! cannot change under a running process.
//!
//! Verity alone proves integrity and not authenticity. The authenticity half
//! is the built-in signature, which the kernel checks against its own keyring
//! when the deployment requires one. This module reports both, and
//! [identity](crate::identity) decides what the pair means.
//!
//! Most deployments enable neither. The ioctl then fails, and that failure is
//! the ordinary answer rather than an error.

use core::ffi::{c_int, c_ulong, c_void};
use std::os::fd::AsRawFd;

/// `FS_IOC_MEASURE_VERITY`, which the kernel declares as
/// `_IOWR('f', 134, struct fsverity_digest)`.
///
/// The generic encoding packs the direction, the size, the type letter, and
/// the number: `(3 << 30) | (4 << 16) | (0x66 << 8) | 134`. ARM64 and
/// `x86_64` both take that encoding, and the v1 floor names those two only.
/// Checked against `include/uapi/linux/fsverity.h` on 2026-08-13.
const FS_IOC_MEASURE_VERITY: c_ulong = 0xC004_6686;

/// `FS_VERITY_HASH_ALG_SHA256`, from the same header.
const HASH_SHA256: u16 = 1;

/// How many digest bytes the buffer below holds.
///
/// SHA-512 is the longest algorithm the header names, so this covers every
/// value the kernel can return, and the call reports which one it used.
const MAX_DIGEST: u16 = 64;

/// `struct fsverity_digest`, with its flexible array given a fixed bound.
///
/// The field that holds the bytes is named for what it carries rather than
/// after the structure, because the structure is the measurement and the field
/// is its bytes.
///
/// The header ends the structure with `__u8 digest[]`, so a caller allocates
/// the header and the digest as one block. This layout is that block.
#[repr(C)]
struct Measurement {
    algorithm: u16,
    /// The buffer length going in, and the digest length coming out.
    size: u16,
    bytes: [u8; MAX_DIGEST as usize],
}

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

/// What the kernel reports about fs-verity on the running image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verity {
    /// The kernel enforces a Merkle tree over this file.
    Enabled {
        /// Whether the digest came from SHA-256 rather than another algorithm.
        sha256: bool,
    },
    /// The file carries no verity, or the filesystem offers none.
    Absent {
        /// Which of the two, in words that name the mechanism.
        reason: &'static str,
    },
}

/// Reads the fs-verity state of the running image.
pub(crate) fn measure(path: &str) -> Verity {
    let Ok(file) = std::fs::File::open(path) else {
        return Verity::Absent {
            reason: "the running image did not open, so no verity state answers",
        };
    };

    let mut measured = Measurement {
        algorithm: 0,
        size: MAX_DIGEST,
        bytes: [0; MAX_DIGEST as usize],
    };

    // SAFETY: `measured` is a live local with the layout that the kernel
    // header states, and its `size` field states the length of the buffer that
    // follows, so the kernel writes inside it. The descriptor belongs to the
    // open file above, and it outlives the call.
    let result = unsafe {
        ioctl(
            file.as_raw_fd(),
            FS_IOC_MEASURE_VERITY,
            (&raw mut measured).cast::<c_void>(),
        )
    };

    if result != 0 {
        // ENODATA means the file carries no verity, and EOPNOTSUPP means the
        // filesystem holds none at all. Neither is a failure of this probe,
        // and both are common, so the reason names the mechanism rather than
        // the number.
        return Verity::Absent {
            reason: "the kernel reports no fs-verity for the running image",
        };
    }

    Verity::Enabled {
        sha256: measured.algorithm == HASH_SHA256,
    }
}

#[cfg(test)]
mod tests {
    use super::{Verity, measure};

    #[test]
    fn a_path_that_does_not_open_reports_absent() {
        // A failed open is never a trusted answer.
        assert!(matches!(
            measure("/proc/self/no-such-file"),
            Verity::Absent { .. }
        ));
    }

    #[test]
    fn the_running_image_answers_one_way_or_the_other() {
        // The boundary control. An ordinary build filesystem enables no
        // verity, so this asserts that the call returns rather than what it
        // returns. A machine that enabled verity would take the other arm.
        let _ = measure("/proc/self/exe");
    }
}
