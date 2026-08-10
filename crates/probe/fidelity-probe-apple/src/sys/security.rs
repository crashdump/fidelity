//! The Security framework boundary.
//!
//! Apple's memory rules govern the whole module. A function whose name holds
//! `Create` or `Copy` returns an object that this module owns and must
//! release. A function whose name holds `Get` returns a borrowed object that
//! this module must not release.

use std::ffi::c_void;

/// The result code that a Security framework call returns.
pub(crate) type OsStatus = i32;

/// An opaque Core Foundation object reference.
type CfTypeRef = *const c_void;

/// A signed index, as Core Foundation defines it.
type CfIndex = isize;

/// The call succeeded.
const SUCCESS: OsStatus = 0;

/// No particular flags, which is the default behavior.
const DEFAULT_FLAGS: u32 = 0;

/// Return cryptographic signing information, which holds the team identifier.
const SIGNING_INFORMATION: u32 = 1 << 1;

/// The UTF-8 string encoding, as Core Foundation numbers it.
const UTF8: u32 = 0x0800_0100;

/// The statuses that state that the operating system rejected the image.
///
/// Every value comes from the `CSCommon.h` header of the macOS SDK, checked on
/// 2026-08-09. A status outside this list is a failure of the call itself, and
/// it becomes a detector-health finding rather than a rejection. Fidelity never
/// converts either one into a clean result.
const REJECTED: &[OsStatus] = &[
    -67063, // errSecCSGuestInvalid, the code identity is invalidated
    -67062, // errSecCSUnsigned, the code object holds no signature
    -67061, // errSecCSSignatureFailed, code or signature are modified
    -67054, // errSecCSBadResource, a sealed resource is missing or bad
    -67050, // errSecCSReqFailed, the code did not satisfy the requirement
    -67045, // errSecCSSignatureInvalid, the signature format is not usable
    -67034, // errSecCSStaticCodeChanged, the disk and the process differ
    -67023, // errSecCSResourceDirectoryFailed, the directory is modified
    -66996, // errSecCSSignatureUntrusted, valid signature, untrusted signer
];

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySelf(flags: u32, out: *mut CfTypeRef) -> OsStatus;
    fn SecCodeCheckValidity(code: CfTypeRef, flags: u32, requirement: CfTypeRef) -> OsStatus;
    fn SecRequirementCreateWithString(text: CfTypeRef, flags: u32, out: *mut CfTypeRef)
    -> OsStatus;
    fn SecCodeCopySigningInformation(code: CfTypeRef, flags: u32, out: *mut CfTypeRef) -> OsStatus;

    static kSecCodeInfoTeamIdentifier: CfTypeRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: CfTypeRef,
        bytes: *const u8,
        length: CfIndex,
        encoding: u32,
        external: u8,
    ) -> CfTypeRef;
    fn CFStringGetCString(text: CfTypeRef, buffer: *mut u8, size: CfIndex, encoding: u32) -> u8;
    fn CFDictionaryGetValue(dictionary: CfTypeRef, key: CfTypeRef) -> CfTypeRef;
    fn CFGetTypeID(object: CfTypeRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFRelease(object: CfTypeRef);
}

/// A Core Foundation object that this module owns and releases.
///
/// The type holds a pointer that a `Create` or `Copy` call returned, so the
/// drop must release it exactly once.
struct Owned(CfTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the constructor accepts a non-null pointer that a `Create`
        // or `Copy` call returned, and nothing else releases it, so this
        // release balances that one reference exactly once.
        unsafe { CFRelease(self.0) }
    }
}

impl Owned {
    /// Takes ownership of a pointer that a `Create` or `Copy` call returned.
    ///
    /// Returns `None` for a null pointer, because a successful status with a
    /// null result would otherwise reach a call that needs an object.
    fn take(pointer: CfTypeRef) -> Option<Self> {
        if pointer.is_null() {
            None
        } else {
            Some(Self(pointer))
        }
    }
}

/// A reference to the code of the running process.
pub(crate) struct SelfCode(Owned);

impl SelfCode {
    /// Asks the operating system for a reference to the running code.
    ///
    /// # Errors
    ///
    /// Returns the status when the call fails, or when it reports success and
    /// returns nothing.
    pub(crate) fn acquire() -> Result<Self, OsStatus> {
        let mut code: CfTypeRef = std::ptr::null();
        // SAFETY: `code` is a live, correctly typed out parameter, and the
        // call writes at most one owned reference into it.
        let status = unsafe { SecCodeCopySelf(DEFAULT_FLAGS, &raw mut code) };
        if status != SUCCESS {
            return Err(status);
        }
        Owned::take(code).map(Self).ok_or(SUCCESS)
    }
}

/// What the operating system answered about one validity check.
pub(crate) enum Verdict {
    /// The image satisfied the check.
    Pass,

    /// The image did not satisfy the check.
    Reject(OsStatus),

    /// The call itself failed, so the check reached no answer.
    Error(OsStatus),
}

/// Asks the operating system whether the running code satisfies a requirement.
///
/// The operating system parses the requirement and evaluates the complete
/// signature. Fidelity does neither, because a byte comparison proves less.
pub(crate) fn check(code: &SelfCode, requirement: &str) -> Verdict {
    let Some(text) = new_string(requirement) else {
        return Verdict::Error(SUCCESS);
    };

    let mut parsed: CfTypeRef = std::ptr::null();
    // SAFETY: `text.0` is a live string that this function owns, and `parsed`
    // is a live out parameter that takes at most one owned reference.
    let status = unsafe { SecRequirementCreateWithString(text.0, DEFAULT_FLAGS, &raw mut parsed) };
    if status != SUCCESS {
        return Verdict::Error(status);
    }
    let Some(parsed) = Owned::take(parsed) else {
        return Verdict::Error(SUCCESS);
    };

    // SAFETY: both references are live and owned for the length of the call.
    let status = unsafe { SecCodeCheckValidity((code.0).0, DEFAULT_FLAGS, parsed.0) };
    if status == SUCCESS {
        Verdict::Pass
    } else if REJECTED.contains(&status) {
        Verdict::Reject(status)
    } else {
        Verdict::Error(status)
    }
}

/// Reads the team identifier that the operating system reports.
///
/// Returns `Ok(None)` when the image carries no team identifier. An ad-hoc
/// signature is the common case, and it is not a failure.
///
/// # Errors
///
/// Returns the status when the call fails.
pub(crate) fn team_identifier(code: &SelfCode) -> Result<Option<String>, OsStatus> {
    let mut information: CfTypeRef = std::ptr::null();
    // SAFETY: the code reference is live, and `information` is a live out
    // parameter that takes at most one owned dictionary.
    let status = unsafe {
        SecCodeCopySigningInformation((code.0).0, SIGNING_INFORMATION, &raw mut information)
    };
    if status != SUCCESS {
        return Err(status);
    }
    let Some(information) = Owned::take(information) else {
        return Err(SUCCESS);
    };

    // SAFETY: the dictionary is live, and the key is a framework constant that
    // lives for the length of the process. `CFDictionaryGetValue` follows the
    // Get rule, so the returned value stays owned by the dictionary.
    let value = unsafe { CFDictionaryGetValue(information.0, kSecCodeInfoTeamIdentifier) };
    Ok(read_string(value))
}

/// Creates a Core Foundation string from Rust text.
fn new_string(text: &str) -> Option<Owned> {
    let length = CfIndex::try_from(text.len()).ok()?;
    // SAFETY: the pointer and the length describe one live slice, and the
    // default allocator copies the bytes before the call returns.
    let created =
        unsafe { CFStringCreateWithBytes(std::ptr::null(), text.as_ptr(), length, UTF8, 0) };
    Owned::take(created)
}

/// The size of the buffer that reads one string out of Core Foundation.
///
/// A team identifier is ten characters. The buffer holds far more, so a value
/// that does not fit states that the dictionary changed shape, and the read
/// reports nothing rather than a cut value.
const READ_BYTES: usize = 512;

/// Reads a borrowed Core Foundation string into Rust text.
///
/// Returns `None` when the value is absent, when it holds another type, or
/// when it does not fit the buffer.
fn read_string(value: CfTypeRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the value is a live, non-null Core Foundation object, so it
    // carries a type identifier that this comparison may read.
    let is_string = unsafe { CFGetTypeID(value) == CFStringGetTypeID() };
    if !is_string {
        return None;
    }

    let mut buffer = [0_u8; READ_BYTES];
    // SAFETY: the value is a live string, and the buffer is a live array of
    // exactly the length that the call receives. The call writes a terminating
    // zero inside that length, or it writes nothing and returns false.
    let copied = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            CfIndex::try_from(READ_BYTES).unwrap_or(0),
            UTF8,
        )
    };
    if copied == 0 {
        return None;
    }

    let end = buffer.iter().position(|byte| *byte == 0)?;
    String::from_utf8(buffer[..end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::{REJECTED, SelfCode, Verdict, check, team_identifier};

    #[test]
    fn the_running_process_has_a_code_reference() {
        assert!(SelfCode::acquire().is_ok(), "the test binary is signed");
    }

    #[test]
    fn a_requirement_that_no_image_satisfies_reports_a_rejection() {
        let Ok(code) = SelfCode::acquire() else {
            unreachable!("the test binary is signed")
        };
        let verdict = check(
            &code,
            "certificate leaf[subject.OU] = \"NOSUCHTEAM\" and anchor apple generic",
        );
        assert!(
            matches!(verdict, Verdict::Reject(_)),
            "an impossible requirement must reject, not error"
        );
    }

    #[test]
    fn a_requirement_that_does_not_parse_reports_an_error() {
        let Ok(code) = SelfCode::acquire() else {
            unreachable!("the test binary is signed")
        };
        let verdict = check(&code, "this is not a requirement");
        assert!(
            matches!(verdict, Verdict::Error(_)),
            "a parse failure is a probe failure, not a rejection"
        );
    }

    #[test]
    fn reading_the_team_identifier_never_fails_on_a_signed_image() {
        let Ok(code) = SelfCode::acquire() else {
            unreachable!("the test binary is signed")
        };
        // Cargo builds an ad-hoc signed test binary, so the value is absent.
        // The read still succeeds, because absence is not a failure.
        assert!(team_identifier(&code).is_ok());
    }

    #[test]
    fn the_rejection_list_holds_the_requirement_failure() {
        // `errSecCSReqFailed` is the status that a repackaged image returns,
        // so a change to the list must never drop it.
        assert!(REJECTED.contains(&-67050));
    }
}
