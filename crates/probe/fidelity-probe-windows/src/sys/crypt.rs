//! The signer-certificate boundary.
//!
//! `WinVerifyTrust` answers whether the machine trusts the image, and it does
//! not say who signed it. The expected-identity tier needs the signer, so this
//! module reads the embedded PKCS #7 message and returns the certificate of
//! the signer, as the bytes that the file itself holds.
//!
//! The walk takes four calls and three handles, and every one of them has to
//! be released on every path. The code below therefore has one exit, and each
//! handle is released in the reverse order that it was taken.
//!
//! Every constant here was checked on 2026-08-13 against the metadata that
//! Microsoft publishes for these interfaces, and each one carries its value.

use core::ffi::c_void;

/// `CERT_QUERY_OBJECT_FILE`. The object is a file rather than a blob.
const OBJECT_FILE: u32 = 1;

/// `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED`.
///
/// An Authenticode signature is a PKCS #7 message inside the image, so this is
/// the one content type this module accepts. A narrower flag than "any" also
/// keeps the call from trying every other type in turn.
const CONTENT_PKCS7_EMBEDDED: u32 = 1024;

/// `CERT_QUERY_FORMAT_FLAG_BINARY`.
const FORMAT_BINARY: u32 = 2;

/// `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING`, which every certificate call
/// below takes.
const ENCODING: u32 = 0x1 | 0x1_0000;

/// `CMSG_SIGNER_CERT_INFO_PARAM`, which names the signer of the message.
const SIGNER_CERT_INFO: u32 = 7;

/// `CERT_FIND_SUBJECT_CERT`, which finds a certificate by issuer and serial.
const FIND_SUBJECT_CERT: u32 = 720_896;

/// `struct CERT_CONTEXT`.
///
/// Only the two encoded fields matter here. The rest keeps the layout right,
/// because a short mirror would read the encoded length from the wrong offset.
#[repr(C)]
struct CertContext {
    encoding_type: u32,
    encoded: *mut u8,
    encoded_len: u32,
    cert_info: *mut c_void,
    store: *mut c_void,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptQueryObject(
        object_type: u32,
        object: *const c_void,
        expected_content: u32,
        expected_format: u32,
        flags: u32,
        encoding: *mut u32,
        content: *mut u32,
        format: *mut u32,
        store: *mut *mut c_void,
        message: *mut *mut c_void,
        context: *mut *const c_void,
    ) -> i32;
    fn CryptMsgGetParam(
        message: *mut c_void,
        param: u32,
        index: u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn CryptMsgClose(message: *mut c_void) -> i32;
    fn CertFindCertificateInStore(
        store: *mut c_void,
        encoding: u32,
        find_flags: u32,
        find_type: u32,
        find_param: *const c_void,
        previous: *const CertContext,
    ) -> *const CertContext;
    fn CertFreeCertificateContext(context: *const CertContext) -> i32;
    fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
}

/// The certificate of the signer of one image, as the bytes the file holds.
///
/// # Errors
///
/// Returns the reason no certificate answered. An unsigned image is the
/// ordinary case, and it is never an error of this probe.
pub(crate) fn signer_certificate(path: &[u16]) -> Result<Vec<u8>, &'static str> {
    let mut store: *mut c_void = core::ptr::null_mut();
    let mut message: *mut c_void = core::ptr::null_mut();

    // SAFETY: `path` is a null-terminated wide string that the caller owns for
    // the whole call, and the two out pointers refer to live locals. Every
    // other output is null, which the interface documents as "not needed".
    let queried = unsafe {
        CryptQueryObject(
            OBJECT_FILE,
            path.as_ptr().cast::<c_void>(),
            CONTENT_PKCS7_EMBEDDED,
            FORMAT_BINARY,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut store,
            &raw mut message,
            core::ptr::null_mut(),
        )
    };

    if queried == 0 {
        return Err("the running image carries no embedded signature");
    }

    let found = read_signer(store, message);

    // Both handles came from the call above, and both are released here
    // whatever the read returned.
    //
    // SAFETY: each handle is one the call above produced, and no other code
    // holds either of them.
    unsafe {
        if !message.is_null() {
            CryptMsgClose(message);
        }
        if !store.is_null() {
            CertCloseStore(store, 0);
        }
    }

    found
}

/// Reads the signer certificate out of an open message and store.
///
/// This is separate so that the caller above owns the two handles and releases
/// them once, on every path that this function can take.
fn read_signer(store: *mut c_void, message: *mut c_void) -> Result<Vec<u8>, &'static str> {
    let mut size: u32 = 0;

    // The first call asks how long the answer is, which is the shape every
    // one of these interfaces takes.
    //
    // SAFETY: `message` is an open message, and a null buffer with a live
    // size pointer is the documented way to ask for the length.
    let sized = unsafe {
        CryptMsgGetParam(
            message,
            SIGNER_CERT_INFO,
            0,
            core::ptr::null_mut(),
            &raw mut size,
        )
    };
    if sized == 0 || size == 0 {
        return Err("the signature names no signer");
    }

    let mut info = vec![0_u8; size as usize];

    // SAFETY: `info` is a live allocation of `size` bytes, which is the length
    // that the call above reported for this parameter.
    let read = unsafe {
        CryptMsgGetParam(
            message,
            SIGNER_CERT_INFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            &raw mut size,
        )
    };
    if read == 0 {
        return Err("the signer of the signature did not read");
    }

    // SAFETY: `info` holds a `CERT_INFO` that the call above wrote, and the
    // store is the one that carries the certificates of this message.
    let context = unsafe {
        CertFindCertificateInStore(
            store,
            ENCODING,
            0,
            FIND_SUBJECT_CERT,
            info.as_ptr().cast::<c_void>(),
            core::ptr::null(),
        )
    };
    if context.is_null() {
        return Err("the store holds no certificate for the signer");
    }

    // SAFETY: `context` is a non-null certificate context that the call above
    // produced, and it stays valid until the release below.
    let bytes = unsafe {
        let encoded = (*context).encoded;
        let length = (*context).encoded_len as usize;
        if encoded.is_null() || length == 0 {
            None
        } else {
            Some(core::slice::from_raw_parts(encoded, length).to_vec())
        }
    };

    // SAFETY: `context` is the context that the call above produced, and no
    // other code holds it.
    unsafe { CertFreeCertificateContext(context) };

    bytes.ok_or("the certificate of the signer holds no bytes")
}

#[cfg(test)]
mod tests {
    use super::signer_certificate;
    use crate::sys::image;

    #[test]
    fn an_unsigned_build_names_no_certificate() {
        // The clean control for this boundary. Cargo signs nothing, so the
        // read must report a gap rather than a certificate. A function that
        // answered here would give every guarded constant a wrong key.
        let Ok(path) = image::path() else {
            panic!("the running image must name a path");
        };
        assert!(signer_certificate(&path).is_err());
    }

    #[test]
    fn a_path_that_names_no_file_reports_a_gap() {
        let mut path: Vec<u16> = "C:\\no-such-file.exe".encode_utf16().collect();
        path.push(0);
        assert!(signer_certificate(&path).is_err());
    }
}
