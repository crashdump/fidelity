//! Reads guarded constants out of a built binary, offline.
//!
//! This is the extraction control that
//! [verification](../../../../docs/plan/05-verification.md) requires, and it
//! records a limit rather than a defense. Both key inputs ship inside the
//! artifact: the salt is a constant in the same expansion as the ciphertext,
//! and the operating system reports the code identity to anybody who asks. An
//! extractor that knows the derivation therefore holds every input, and it
//! needs no secret of its own.
//!
//! ```text
//! FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
//!     cargo build --release --example guarded -p fidelity
//! cargo run --release --example extract -p fidelity-cipher -- \
//!     target/release/examples/guarded
//! ```
//!
//! The second argument is the code identity that the running image reports,
//! and it defaults to the empty value that an unbound build uses. On a bound
//! build pass the team identifier or the certificate digest alone, without the
//! kind that `FIDELITY_CODE_IDENTITY` names in front of it, because the
//! running image reports the material and never the kind. Both are public.
//!
//! Every argument after that is a literal that the build guarded. The control
//! then reports whether it recovered each one, and it exits non-zero when it
//! did not. That is the form the release gate runs. With no literal it prints
//! a sample instead, which is the form an attacker runs.
//!
//! The extractor knows no seed and needs none. The seed reaches the salt at
//! build time, and the salt is in the file.
//!
//! # What this measures
//!
//! Pairing a salt with a ciphertext is the only work, and this control does it
//! by trying every pair inside a window. That is the slowest way. An attacker
//! who disassembles one call site reads both addresses directly, because
//! `__guarded` is inlined and loads them, so treat the cost below as an upper
//! bound rather than as a difficulty.

/// The shortest guarded constant that the macro accepts.
const MIN: usize = 8;

/// The longest run that this control reports as one constant.
const MAX: usize = 64;

/// How far from a candidate salt the ciphertext is looked for.
///
/// Measured on a release build on 2026-08-11: one constant put its ciphertext
/// 16 bytes in front of its salt, and another put it 1346 bytes behind. The
/// compiler orders the constant pool by size and alignment, not by expansion,
/// so the window reaches both ways.
const WINDOW: usize = 2048;

/// How many candidates the sample prints, and how long each one must be.
const SAMPLE: usize = 20;
const SAMPLE_MIN: usize = 15;

/// The alphabet that the stream preserves, as its size and its first byte.
const ALPHABET: u8 = 95;
const FIRST: u8 = 0x20;

/// The bytes that a secret is made of, in practice.
///
/// The stream is alphabet-preserving, so every wrong key also gives printable
/// text. Printability is therefore no filter at all, and an attacker needs a
/// semantic one instead. This is that filter. It is the weakest part of the
/// attack, and it is not a defense that anybody chose.
fn plausible(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_' | b':' | b'@')
}

/// What one key adds at each offset, through the public interface only.
///
/// Decrypting a buffer that holds the first letter of the alphabet reports
/// exactly that, because the first letter is the zero of the alphabet. One
/// recovery serves every offset, because byte `i` depends on the key and on
/// `i` alone. Without this the control would derive a key for each pair, and
/// the search would take hours rather than seconds.
fn keystream(key: &[u8; 32]) -> [u8; MAX] {
    let mut probe = [FIRST; MAX];
    fidelity_cipher::decrypt(key, &mut probe);
    let mut stream = [0_u8; MAX];
    for (out, value) in stream.iter_mut().zip(probe) {
        *out = value - FIRST;
    }
    stream
}

/// One decrypted byte, by the fast path that the search uses.
fn clear(cipher: u8, stream: u8) -> u8 {
    (cipher - FIRST + stream) % ALPHABET + FIRST
}

/// Proves that the fast path agrees with the cipher it stands in for.
///
/// The search below never calls `decrypt`, so an error here would make the
/// control report that it recovered nothing and look like a defense. This runs
/// first, and it fails loudly.
fn self_check() {
    let salt = fidelity_cipher::derive_salt(b"extract self check", b"api.example.com");
    let key = fidelity_cipher::derive_key(&salt, b"");
    let cipher = fidelity_cipher::encrypt(&key, b"api.example.com");
    let stream = keystream(&key);
    let fast: Vec<u8> = cipher
        .iter()
        .zip(stream)
        .map(|(byte, step)| clear(*byte, step))
        .collect();
    assert_eq!(
        fast, b"api.example.com",
        "the fast path must agree with decrypt"
    );
}

fn main() {
    self_check();

    let mut arguments = std::env::args().skip(1);
    let Some(path) = arguments.next() else {
        println!("usage: extract <binary> [code identity]");
        return;
    };
    let identity = arguments.next().unwrap_or_default();

    let Ok(image) = std::fs::read(&path) else {
        println!("could not read {path}");
        return;
    };

    println!("file      : {path} ({} bytes)", image.len());
    println!("identity  : {identity:?}");

    let expected: Vec<String> = arguments.collect();
    let mut recovered = vec![false; expected.len()];
    let mut sample: Vec<String> = Vec::new();
    let mut candidates = 0_u64;
    let mut pairs = 0_u64;
    let mut plain = [0_u8; MAX];

    for at in 0..image.len().saturating_sub(16) {
        let Some(window) = image.get(at..at + 16) else {
            continue;
        };
        let Ok(salt) = <[u8; 16]>::try_from(window) else {
            continue;
        };
        let stream = keystream(&fidelity_cipher::derive_key(&salt, identity.as_bytes()));

        let from = at.saturating_sub(WINDOW);
        let to = (at + WINDOW).min(image.len());
        for start in from..to {
            pairs += 1;
            let mut length = 0;
            while length < MAX {
                let Some(byte) = image.get(start + length) else {
                    break;
                };
                if !fidelity_cipher::in_alphabet(&[*byte]) {
                    break;
                }
                let decrypted = clear(*byte, stream[length]);
                if !plausible(decrypted) {
                    break;
                }
                plain[length] = decrypted;
                length += 1;
            }
            if length < MIN {
                continue;
            }
            let Ok(text) = core::str::from_utf8(&plain[..length]) else {
                continue;
            };
            candidates += 1;
            for (index, literal) in expected.iter().enumerate() {
                if text == literal {
                    recovered[index] = true;
                }
            }
            if expected.is_empty() && length >= SAMPLE_MIN && sample.len() < SAMPLE {
                sample.push(text.to_owned());
            }
        }
    }

    println!("pairs     : {pairs}");
    println!("candidates: {candidates}");

    if expected.is_empty() {
        println!(
            "sample    : the first {} of {SAMPLE_MIN} characters or more",
            sample.len()
        );
        for text in &sample {
            println!("  {text}");
        }
        return;
    }

    let mut missing = 0_usize;
    for (literal, found) in expected.iter().zip(&recovered) {
        if *found {
            println!("  RECOVERED {literal}");
        } else {
            println!("  missing   {literal}");
            missing += 1;
        }
    }
    if missing > 0 {
        println!(
            "{missing} of {} guarded constants stayed hidden",
            expected.len()
        );
        std::process::exit(1);
    }
    println!("every guarded constant came out of the artifact, with no secret but the identity");
}
