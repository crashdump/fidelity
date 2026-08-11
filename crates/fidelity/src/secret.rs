use core::fmt;
use core::hint::black_box;
use core::ops::Deref;

use fidelity_cipher::{decrypt, derive_key};

use crate::Handle;

/// A guarded value, for one scope.
///
/// [`guarded!`](crate::guarded) returns this. It derefs to `str`, so it works
/// where the literal worked. It wipes its buffer on drop, so a plaintext lives
/// for one scope rather than for the life of the process.
///
/// The wipe is best effort. A compiler may keep a copy in a register or in a
/// spilled stack slot that the wipe does not reach, so this bounds exposure
/// rather than removing it.
///
/// There is no cache. A read decrypts every time, because one cached plaintext
/// would let one hook dump every guarded value at once.
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Wraps decrypted bytes.
    const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// The value as text.
    ///
    /// The stream keeps every byte inside printable ASCII, whatever the key,
    /// so the conversion always succeeds. The empty fallback exists because
    /// the compiler cannot prove that, and it never runs.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes).unwrap_or("")
    }
}

impl<const N: usize> Deref for Secret<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.bytes.fill(0);
        // The read stops the compiler from removing a write that nothing
        // observes afterwards.
        black_box(&self.bytes);
    }
}

/// Prints a placeholder, never the value.
///
/// A guarded value that a log line prints would defeat the whole mechanism, so
/// the format never reaches the bytes.
impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(..)")
    }
}

/// Decrypts one guarded constant.
///
/// [`guarded!`](crate::guarded) emits the call. It is not part of the
/// supported surface, and it carries no compatibility promise.
///
/// `BOUND` states whether this build binds to code identity. It is a constant,
/// so an attacker cannot flip a runtime flag and skip the binding.
///
/// A wrong identity gives a wrong value. There is no error path, so there is
/// nothing here for an attacker to invert.
#[doc(hidden)]
#[inline(always)]
#[expect(
    clippy::inline_always,
    reason = "the copy at each call site is the point: it leaves no shared decryptor to hook"
)]
#[must_use]
pub fn __guarded<const N: usize, const BOUND: bool>(
    handle: &Handle,
    salt: &[u8; 16],
    value: &[u8; N],
) -> Secret<N> {
    let identity: &[u8] = if BOUND { handle.code_identity() } else { &[] };
    let key = derive_key(salt, identity);
    let mut bytes = *value;
    decrypt(&key, &mut bytes);
    Secret::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn a_secret_derefs_to_its_text() {
        let secret = Secret::new(*b"api.example.com");
        assert_eq!(&*secret, "api.example.com");
    }

    #[test]
    fn a_secret_compares_against_a_literal() {
        let secret = Secret::new(*b"api.example.com");
        assert_eq!(secret.as_str(), "api.example.com");
    }

    #[test]
    fn the_debug_output_never_holds_the_value() {
        let secret = Secret::new(*b"api.example.com");
        let shown = format!("{secret:?}");
        assert!(!shown.contains("example"), "{shown}");
        assert!(shown.contains("Secret"), "{shown}");
    }

    #[test]
    fn a_secret_works_where_a_string_slice_works() {
        fn takes(value: &str) -> usize {
            value.len()
        }
        let secret = Secret::new(*b"api.example.com");
        assert_eq!(takes(&secret), 15);
    }
}
