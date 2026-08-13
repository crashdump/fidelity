//! Key derivation and the stream that guarded constants use.
//!
//! The build side encrypts a host literal, and the runtime side decrypts it.
//! Both sides call this crate, so the two can never drift apart.
//!
//! # Why the stream preserves the alphabet
//!
//! A wrong key must give a wrong value, never an error. Byte encryption fails
//! that test: random bytes are almost never valid UTF-8, so a decode failure
//! would tell an attacker that the key is wrong. That failure is the branch
//! that guarded constants exist to remove.
//!
//! The stream therefore works inside the printable ASCII alphabet. Every key,
//! right or wrong, gives printable ASCII, so nothing downstream can fail on
//! the shape of the result.
//!
//! # What this is not
//!
//! This is not a confidentiality mechanism. An attacker who holds the binary
//! holds the build seed, and the code identity is a value the operating system
//! reports to anybody who asks. The mechanism binds a value to one build of
//! one signed application. It does not hide it.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise.

#![forbid(unsafe_code)]

pub mod binding;
mod sha256;

pub use sha256::{hex, sha256};

/// The lowest byte of the alphabet, which is the space character.
pub const FIRST: u8 = 0x20;

/// The highest byte of the alphabet, which is the tilde character.
pub const LAST: u8 = 0x7E;

/// The number of characters in the alphabet.
pub const ALPHABET: u16 = (LAST - FIRST) as u16 + 1;

/// The shortest guarded value, in bytes.
///
/// A short value gives an attacker few possibilities to try, and a two-byte
/// constant is worth nothing to guard. The macro rejects anything shorter, so
/// the rule fails the build rather than the run.
pub const MIN_BYTES: usize = 8;

/// The number of keystream bytes that one character consumes.
///
/// One byte reduced by the alphabet size would favor the first 66 characters
/// three times over the rest. Two bytes cut that bias far below anything the
/// threat model cares about, and they cost nothing.
const BYTES_PER_CHARACTER: usize = 2;

/// Reports whether every byte sits inside the alphabet.
#[must_use]
pub fn in_alphabet(value: &[u8]) -> bool {
    value.iter().all(|byte| (FIRST..=LAST).contains(byte))
}

/// Derives the salt of one guarded constant, at build time only.
///
/// The salt carries the per-build seed, so the seed itself never reaches the
/// shipped binary. Two builds with two seeds give two salts, and therefore two
/// different guarded values, which is what removes the monoculture.
///
/// The literal takes part as well, so two constants in one build never share a
/// key and never share a keystream.
#[must_use]
pub fn derive_salt(seed: &[u8], literal: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(seed.len() + literal.len() + 16);
    for part in [seed, literal] {
        input.extend_from_slice(&(part.len() as u64).to_le_bytes());
        input.extend_from_slice(part);
    }
    let digest = sha256(&input);
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}

/// Derives the key for one guarded constant.
///
/// The two inputs are the per-constant salt, which already carries the build
/// seed, and the code identity that the operating system reports. Each part
/// carries its length, so two different splits can never produce the same
/// input.
///
/// The identity is empty when the host stated that this build binds to no
/// code identity. The build side and the runtime side then agree on an empty
/// value, and the guard reduces to the per-build seed alone.
#[must_use]
pub fn derive_key(salt: &[u8; 16], identity: &[u8]) -> [u8; 32] {
    // A read happens on the host's own path, so the derivation allocates
    // nothing. A part longer than the cap collapses to its own digest first,
    // which keeps the buffer fixed and keeps every part unambiguous.
    let mut reduced;
    let mut input = [0_u8; CAP * 2 + 16];
    let mut filled = 0;

    for part in [salt.as_slice(), identity] {
        let part = if part.len() > CAP {
            reduced = sha256(part);
            reduced.as_slice()
        } else {
            part
        };
        debug_assert!(part.len() <= CAP);
        input[filled..filled + 8].copy_from_slice(&(part.len() as u64).to_le_bytes());
        filled += 8;
        input[filled..filled + part.len()].copy_from_slice(part);
        filled += part.len();
    }
    sha256(&input[..filled])
}

/// The longest part that the derivation takes without a reduction.
///
/// Every identity value that a platform reports fits: a team identifier is
/// ten bytes, and a digest is thirty-two.
const CAP: usize = 64;

/// Turns a host literal into a guarded value.
///
/// # Panics
///
/// Panics when a byte sits outside the alphabet. Only the build side calls
/// this, and the macro checks the literal first, so the panic states a defect
/// in Fidelity rather than a host mistake.
#[must_use]
pub fn encrypt(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    assert!(in_alphabet(plain), "the literal leaves the alphabet");
    let mut output = plain.to_vec();
    step(key, &mut output, Direction::Forward);
    output
}

/// Turns a guarded value back into the host literal.
///
/// A wrong key gives a wrong value. It never fails, and it never leaves the
/// alphabet, so the caller has nothing to branch on.
pub fn decrypt(key: &[u8; 32], value: &mut [u8]) {
    step(key, value, Direction::Backward);
}

/// Which way the stream moves through the alphabet.
#[derive(Clone, Copy)]
enum Direction {
    Forward,
    Backward,
}

/// Moves every byte through the alphabet by its keystream amount.
fn step(key: &[u8; 32], value: &mut [u8], direction: Direction) {
    // The keystream is `sha256(key || counter)`, which needs one primitive
    // rather than two. Each constant carries its own salt, so each carries its
    // own key, and no two constants share a keystream.
    let mut block = [0_u8; 32];
    let mut input = [0_u8; 36];
    input[..32].copy_from_slice(key);

    for (index, byte) in value.iter_mut().enumerate() {
        let offset = index * BYTES_PER_CHARACTER;
        let position = offset % 32;
        if position == 0 {
            let counter = u32::try_from(offset / 32).unwrap_or(u32::MAX);
            input[32..].copy_from_slice(&counter.to_le_bytes());
            block = sha256(&input);
        }

        let amount = u16::from_le_bytes([block[position], block[position + 1]]) % ALPHABET;
        let current = u16::from(*byte - FIRST);
        let moved = match direction {
            Direction::Forward => (current + amount) % ALPHABET,
            Direction::Backward => (current + ALPHABET - amount) % ALPHABET,
        };
        // The result is below the alphabet size, so the sum stays a byte.
        *byte = FIRST + u8::try_from(moved).unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALPHABET, FIRST, LAST, MIN_BYTES, decrypt, derive_key, derive_salt, encrypt, in_alphabet,
    };

    const SALT: [u8; 16] = [7; 16];

    fn key(identity: &[u8]) -> [u8; 32] {
        derive_key(&SALT, identity)
    }

    #[test]
    fn the_alphabet_holds_every_printable_character() {
        assert_eq!(ALPHABET, 95);
        assert!(in_alphabet(b"api.example.com"));
        assert!(in_alphabet(&[FIRST, LAST]));
    }

    #[test]
    fn a_control_character_leaves_the_alphabet() {
        assert!(!in_alphabet(b"line\nbreak"));
    }

    #[test]
    fn a_round_trip_returns_the_literal() {
        let key = key(b"TEAM123456");
        let mut value = encrypt(&key, b"api.example.com");
        decrypt(&key, &mut value);
        assert_eq!(value, b"api.example.com");
    }

    #[test]
    fn a_long_value_crosses_a_keystream_block() {
        // Two keystream bytes per character means one block covers sixteen.
        let literal = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
        let key = key(b"TEAM123456");
        let mut value = encrypt(&key, literal);
        decrypt(&key, &mut value);
        assert_eq!(value, literal);
    }

    #[test]
    fn the_guarded_value_never_holds_the_literal() {
        let value = encrypt(&key(b"TEAM123456"), b"api.example.com");
        assert_ne!(value, b"api.example.com");
    }

    #[test]
    fn another_identity_gives_another_value() {
        let literal = b"api.example.com";
        let value = encrypt(&key(b"TEAM123456"), literal);
        let mut wrong = value.clone();
        decrypt(&key(b"OTHERTEAM1"), &mut wrong);
        assert_ne!(wrong, literal);
    }

    #[test]
    fn another_seed_gives_another_value() {
        let first = derive_salt(b"one", b"api.example.com");
        let second = derive_salt(b"two", b"api.example.com");
        assert_ne!(
            first, second,
            "a rotated seed must change the guarded value"
        );
        assert_ne!(
            encrypt(&derive_key(&first, b"TEAM"), b"api.example.com"),
            encrypt(&derive_key(&second, b"TEAM"), b"api.example.com")
        );
    }

    #[test]
    fn another_salt_gives_another_value() {
        let other = [9_u8; 16];
        let first = encrypt(&derive_key(&SALT, b"TEAM"), b"api.example.com");
        let second = encrypt(&derive_key(&other, b"TEAM"), b"api.example.com");
        assert_ne!(first, second);
    }

    #[test]
    fn the_length_prefix_separates_the_parts() {
        // Without a length prefix these two splits would hash the same bytes.
        assert_ne!(derive_salt(b"ab", b"cd"), derive_salt(b"abc", b"d"));
    }

    #[test]
    fn every_wrong_key_gives_a_well_formed_value() {
        // One decode failure is an oracle, so this is the load-bearing test.
        let literal = b"api.example.com/v1/token";
        let value = encrypt(&key(b"TEAM123456"), literal);
        for attempt in 0_u32..100_000 {
            let wrong = derive_key(&derive_salt(&attempt.to_le_bytes(), b"x"), b"attacker");
            let mut guess = value.clone();
            decrypt(&wrong, &mut guess);
            assert!(in_alphabet(&guess), "attempt {attempt} left the alphabet");
            assert!(
                std::str::from_utf8(&guess).is_ok(),
                "attempt {attempt} produced invalid text"
            );
        }
    }

    #[test]
    fn a_wrong_key_almost_never_returns_the_literal() {
        let literal = b"api.example.com";
        let value = encrypt(&key(b"TEAM123456"), literal);
        let mut matches = 0_u32;
        for attempt in 0_u32..10_000 {
            let wrong = derive_key(&derive_salt(&attempt.to_le_bytes(), b"x"), b"attacker");
            let mut guess = value.clone();
            decrypt(&wrong, &mut guess);
            if guess == literal {
                matches += 1;
            }
        }
        assert_eq!(matches, 0, "a wrong key recovered the literal");
    }

    #[test]
    fn the_shortest_value_is_eight_bytes() {
        assert_eq!(MIN_BYTES, 8);
    }
}
