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
//! Every argument after that is a literal that the build guarded. Prefix
//! arbitrary bytes with `hex:`. The control reports whether it recovered each
//! value, and it exits non-zero when it recovered none. With no value it
//! prints a sample, which is the form an attacker runs.
//!
//! The extractor knows no seed and needs none. The seed reaches the salt at
//! build time, and the salt is in the file.
//!
//! # What a run proves
//!
//! The gate form states the literals, so it encrypts each one under every
//! candidate salt and looks the result up in an index of the file. It needs no
//! window. The sample form states none, so it walks a window around each
//! candidate salt and prints what decrypts to plausible text.
//!
//! A run passes when it recovers one constant, and it records how many it
//! recovered. Whether a ciphertext sits in the constant pool depends on the
//! target. Measured on macOS on 2026-08-13, from one source with one seed: ARM64
//! put both ciphertexts in the pool, and `x86_64` put one in instruction
//! immediates. Measured on Windows on 2026-08-21, `x86_64` put both there. A
//! byte scan cannot reach an immediate. An attacker who disassembles one call
//! site reads it directly. Thus, an unrecovered constant has no protection.
//!
//! Neither artifact holds a literal in the clear. The `guarded-no-plaintext`
//! control states that separately, because it holds on every target and this
//! one does not.

/// The shortest guarded constant that the macro accepts.
const MIN: usize = 8;

/// The longest run that this control reports as one constant.
const MAX: usize = 64;

/// How far from a candidate salt the ciphertext is looked for.
///
/// The sample form uses this. The gate form states its literals, so it looks
/// them up exactly and no window bounds it.
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

/// One exact value that the release gate asks the extractor to recover.
struct Expected {
    label: String,
    plain: Vec<u8>,
    kind: ExpectedKind,
}

/// The stream that the macro used for one expected value.
#[derive(Clone, Copy)]
enum ExpectedKind {
    Text,
    Bytes,
}

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

    let image = match std::fs::read(&path) {
        Ok(image) => image,
        Err(error) => {
            eprintln!("the extractor could not read {path}: {error}");
            std::process::exit(1);
        }
    };

    println!("file      : {path} ({} bytes)", image.len());
    println!("identity  : {identity:?}");

    let mut expected = Vec::new();
    for argument in arguments {
        match parse_expected(argument) {
            Ok(value) => expected.push(value),
            Err(error) => {
                eprintln!("the extractor refused an expected value: {error}");
                std::process::exit(1);
            }
        }
    }

    // The gate form states what it looks for, so it recovers each literal
    // exactly and needs no window at all. The sample form below is the one an
    // attacker runs, and it enumerates rather than confirms.
    if !expected.is_empty() {
        report(&expected, &recover(&image, &identity, &expected));
        return;
    }

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
            if length >= SAMPLE_MIN && sample.len() < SAMPLE {
                sample.push(text.to_owned());
            }
        }
    }

    println!("pairs     : {pairs}");
    println!("candidates: {candidates}");
    println!(
        "sample    : the first {} of {SAMPLE_MIN} characters or more",
        sample.len()
    );
    for text in &sample {
        println!("  {text}");
    }
}

/// Recovers each stated literal, with no window and no search.
///
/// The gate states the literals, so this needs no candidate enumeration at
/// all. For each position it treats the bytes as a salt, encrypts the literal
/// that it already knows, and looks the result up in an index of the file.
///
/// That answers on any layout. A window around the salt cannot, because the
/// compiler orders the constant pool by size and alignment and the distance
/// between a salt and its ciphertext changes with the target. Measured on
/// 2026-08-13: the same source put one pair 16 bytes apart on ARM64 and more
/// than 2048 bytes apart on `x86_64`, so a window that held on one machine
/// reported the constant as hidden on the other. A control that reports a
/// recoverable constant as hidden overstates what the guard does.
fn recover(image: &[u8], identity: &str, expected: &[Expected]) -> Vec<bool> {
    // Where each eight-byte run sits. Every guarded constant is at least MIN
    // bytes long, so eight bytes select the few places worth comparing.
    let mut index: std::collections::HashMap<[u8; 8], Vec<usize>> =
        std::collections::HashMap::new();
    for at in 0..image.len().saturating_sub(MIN) {
        let Some(window) = image.get(at..at + MIN) else {
            continue;
        };
        let Ok(head) = <[u8; MIN]>::try_from(window) else {
            continue;
        };
        index.entry(head).or_default().push(at);
    }

    let mut recovered = vec![false; expected.len()];
    for at in 0..image.len().saturating_sub(16) {
        if recovered.iter().all(|found| *found) {
            break;
        }
        let Some(window) = image.get(at..at + 16) else {
            continue;
        };
        let Ok(salt) = <[u8; 16]>::try_from(window) else {
            continue;
        };
        let key = fidelity_cipher::derive_key(&salt, identity.as_bytes());

        for (which, value) in expected.iter().enumerate() {
            if recovered[which] {
                continue;
            }
            let cipher = match value.kind {
                ExpectedKind::Text => fidelity_cipher::encrypt(&key, &value.plain),
                ExpectedKind::Bytes => fidelity_cipher::encrypt_bytes(&key, &value.plain),
            };
            let Some(head) = cipher.get(..MIN) else {
                continue;
            };
            let Ok(head) = <[u8; MIN]>::try_from(head) else {
                continue;
            };
            let Some(places) = index.get(&head) else {
                continue;
            };
            recovered[which] = places
                .iter()
                .any(|&start| image.get(start..start + cipher.len()) == Some(cipher.as_slice()));
        }
    }
    recovered
}

/// Prints what came out, and exits non-zero when nothing did.
///
/// One recovery establishes the ceiling, which is what this control records,
/// so a run that reaches one constant passes and states how many it reached.
/// A run that reaches none fails, because an extractor that recovers nothing
/// is measuring itself rather than the artifact.
fn report(expected: &[Expected], recovered: &[bool]) {
    for (value, found) in expected.iter().zip(recovered) {
        if *found {
            println!("  RECOVERED {}", value.label);
        } else {
            println!("  missing   {}", value.label);
        }
    }

    let found = recovered.iter().filter(|found| **found).count();
    if found == 0 {
        println!(
            "0 of {} guarded constants came out, so every one stayed hidden",
            expected.len()
        );
        std::process::exit(1);
    }
    println!(
        "{found} of {} guarded constants came out of the artifact, with no secret but the identity",
        expected.len()
    );
}

/// Parses a text value or a `hex:` byte value.
fn parse_expected(argument: String) -> Result<Expected, String> {
    let Some(hex) = argument.strip_prefix("hex:") else {
        return Ok(Expected {
            plain: argument.as_bytes().to_vec(),
            label: argument,
            kind: ExpectedKind::Text,
        });
    };

    let mut pairs = hex.as_bytes().chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err(String::from("a hex value must hold pairs of digits"));
    }
    let mut plain = Vec::with_capacity(hex.len() / 2);
    for pair in &mut pairs {
        let Some(high) = hex_digit(pair[0]) else {
            return Err(String::from(
                "a hex value holds a character that is not a digit",
            ));
        };
        let Some(low) = hex_digit(pair[1]) else {
            return Err(String::from(
                "a hex value holds a character that is not a digit",
            ));
        };
        plain.push((high << 4) | low);
    }
    if plain.len() < MIN {
        return Err(format!("a value must hold {MIN} bytes or more"));
    }
    Ok(Expected {
        label: argument,
        plain,
        kind: ExpectedKind::Bytes,
    })
}

/// Converts one ASCII hex digit.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
