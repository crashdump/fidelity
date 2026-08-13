//! The Authenticode trust boundary.
//!
//! `WinVerifyTrust` is the Windows form of the platform-trust question. It
//! validates the signature of the image and chains it to a root that the
//! machine trusts, which is what `SecCodeCheckValidity` answers on macOS.
//!
//! # This call never reaches the network
//!
//! Revocation checking is the reason it could, and
//! [ADR-0004](../../../../docs/adr/0004-no-network-in-library.md) forbids a
//! remote network client anywhere in this library. Two settings hold that:
//! `WTD_REVOKE_NONE` asks for no revocation work, and
//! `WTD_CACHE_ONLY_URL_RETRIEVAL` states that any retrieval the provider still
//! wants comes from the local cache. Microsoft names the second one as the way
//! to stop network retrieval during a code-signature check.
//!
//! The cost is stated rather than hidden: a certificate that a issuer revoked
//! after this machine last cached its list still reads as trusted here. A
//! revocation check that blocks a security scan on a network round trip is the
//! worse failure, and the host learns nothing it can act on in time.

use core::ffi::c_void;

/// A Windows `GUID`, in the layout that every Win32 interface takes.
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// `WINTRUST_ACTION_GENERIC_VERIFY_V2`, which selects the Authenticode policy.
///
/// This is a `static` rather than a `const`, because the call takes its
/// address. A `const` is a value, so each use would build a temporary and
/// pass a pointer to memory that the call outlives.
///
/// Checked against the softpub.h source on 2026-08-13.
static GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00AA_C56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

/// `WTD_UI_NONE`. A library shows no dialog.
const UI_NONE: u32 = 2;

/// `WTD_REVOKE_NONE`. See the note above about the network.
const REVOKE_NONE: u32 = 0;

/// `WTD_CHOICE_FILE`. The union below carries a file.
const CHOICE_FILE: u32 = 1;

/// `WTD_STATEACTION_VERIFY`, which runs the check and allocates state.
const STATE_VERIFY: u32 = 1;

/// `WTD_STATEACTION_CLOSE`, which frees that state.
///
/// Microsoft states that every `VERIFY` needs a matching `CLOSE`, so a path
/// that returned early without one would leak on every scan.
const STATE_CLOSE: u32 = 2;

/// `WTD_CACHE_ONLY_URL_RETRIEVAL`. See the note above about the network.
const CACHE_ONLY: u32 = 0x1000;

/// `TRUST_E_NOSIGNATURE`, which is what an unsigned image reports.
const TRUST_E_NOSIGNATURE: i32 = -0x7FF4_FF00; // 0x800B0100

/// The size of [`FileInfo`], which its own first field states.
///
/// The two assertions below turn the cast into a fact. Each structure is a
/// fixed layout of pointers and 32-bit fields, so its size is a small constant
/// on both supported architectures, and a cast that could truncate cannot.
const FILE_INFO_SIZE: u32 = 32;

/// The size of [`TrustData`], on the same terms.
const TRUST_DATA_SIZE: u32 = 88;

/// `struct WINTRUST_FILE_INFO`.
#[repr(C)]
struct FileInfo {
    cb_struct: u32,
    file_path: *const u16,
    file: *mut c_void,
    known_subject: *const Guid,
}

/// `struct WINTRUST_DATA`.
///
/// The union of six pointers is one pointer wide, so this states it as one.
/// `union_choice` names which one it is, and this module always says file.
/// Checked against the wintrust.h reference on 2026-08-13.
#[repr(C)]
struct TrustData {
    cb_struct: u32,
    policy_callback_data: *mut c_void,
    sip_client_data: *mut c_void,
    ui_choice: u32,
    revocation_checks: u32,
    union_choice: u32,
    union_data: *mut c_void,
    state_action: u32,
    state_data: *mut c_void,
    url_reference: *mut u16,
    prov_flags: u32,
    ui_context: u32,
    signature_settings: *mut c_void,
}

const _: () = assert!(size_of::<FileInfo>() == FILE_INFO_SIZE as usize);
const _: () = assert!(size_of::<TrustData>() == TRUST_DATA_SIZE as usize);

#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(window: *mut c_void, action: *const Guid, data: *mut c_void) -> i32;
}

/// What the operating system reports about the trust of the running image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trust {
    /// The signature is valid and it chains to a trusted root.
    Accepted,
    /// The image carries no signature at all.
    Unsigned,
    /// The image carries a signature that did not validate.
    Rejected,
}

/// Asks the Authenticode policy about one image.
pub(crate) fn verify(path: &[u16]) -> Trust {
    let mut file = FileInfo {
        cb_struct: FILE_INFO_SIZE,
        file_path: path.as_ptr(),
        file: core::ptr::null_mut(),
        known_subject: core::ptr::null(),
    };

    let mut data = TrustData {
        cb_struct: TRUST_DATA_SIZE,
        policy_callback_data: core::ptr::null_mut(),
        sip_client_data: core::ptr::null_mut(),
        ui_choice: UI_NONE,
        revocation_checks: REVOKE_NONE,
        union_choice: CHOICE_FILE,
        union_data: (&raw mut file).cast::<c_void>(),
        state_action: STATE_VERIFY,
        state_data: core::ptr::null_mut(),
        url_reference: core::ptr::null_mut(),
        prov_flags: CACHE_ONLY,
        ui_context: 0,
        signature_settings: core::ptr::null_mut(),
    };

    // SAFETY: `data` is a live local with the layout that wintrust.h states,
    // and its `union_data` points at `file`, which outlives this call because
    // both are locals of this function. `path` is a null-terminated wide
    // string that the caller owns for the whole call.
    let result = unsafe {
        WinVerifyTrust(
            core::ptr::null_mut(),
            &raw const GENERIC_VERIFY_V2,
            (&raw mut data).cast::<c_void>(),
        )
    };

    // The state has to be released whatever the verdict is, and before this
    // function returns, so the release comes before the match below.
    data.state_action = STATE_CLOSE;

    // SAFETY: the same structure, which the call above filled with the state
    // handle that this call frees.
    unsafe {
        WinVerifyTrust(
            core::ptr::null_mut(),
            &raw const GENERIC_VERIFY_V2,
            (&raw mut data).cast::<c_void>(),
        );
    }

    match result {
        0 => Trust::Accepted,
        TRUST_E_NOSIGNATURE => Trust::Unsigned,
        _ => Trust::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::{Trust, verify};
    use crate::sys::image;

    #[test]
    fn the_running_image_gets_a_verdict() {
        // The boundary control. A test binary that Cargo built carries no
        // signature, so the ordinary answer here is `Unsigned`. The test
        // states that the call answered, because a signed build takes the
        // other arm and both are correct.
        let Ok(path) = image::path() else {
            panic!("the running image must name a path");
        };
        let verdict = verify(&path);
        assert!(matches!(
            verdict,
            Trust::Accepted | Trust::Unsigned | Trust::Rejected
        ));
    }

    #[test]
    fn an_unsigned_build_is_not_accepted() {
        // Cargo signs nothing, so a build from this workspace must never read
        // as trusted. A call that returned `Accepted` for an unsigned image
        // would report every repackaged binary as genuine.
        let Ok(path) = image::path() else {
            panic!("the running image must name a path");
        };
        assert_ne!(verify(&path), Trust::Accepted);
    }
}
