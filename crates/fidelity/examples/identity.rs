//! Reports what the identity detectors see in this process.
//!
//! The argument states what the host pins, and its shape selects the platform
//! that takes it. A code requirement is an Apple value:
//!
//! ```text
//! cargo run --example identity -- 'anchor apple generic and \
//!     certificate leaf[subject.OU] = "YOURTEAMID"'
//! ```
//!
//! Sign the built binary with your distribution certificate, run it again, and
//! compare. That pair is the clean control and the hostile control for image
//! identity on one machine.
//!
//! A digest of 64 hexadecimal characters is a Linux or a Windows value:
//!
//! ```text
//! cargo run --example identity -- $(sha256sum ./identity | cut -d" " -f1)
//! ```
//!
//! Append one byte to the built binary and run it again with the same digest.
//! An appended byte leaves an ELF image runnable and changes its content, so
//! that pair is the repackage control on Linux.
//!
//! One alphanumeric token is an iOS team identifier:
//!
//! ```text
//! cargo run --example identity --target aarch64-apple-ios-sim -- ABCDE12345
//! ```
//!
//! An image that names no team reports `High` against any pinned team, and an
//! image that names one reports clean against its own. Apple refuses to launch
//! a self-signed image that carries the team entitlement, so only the first
//! half of that pair runs here. See `tests/platform/README.md`.

use fidelity::{
    Action, AuthenticodeThumbprint, Choice, CodeRequirement, ContentDigest, ExpectedIdentity,
    Outcome, SignalStrength, TeamIdentifier,
};

/// Whether the argument is a digest rather than a code requirement.
///
/// The two forms cannot be confused: a code requirement holds spaces and
/// punctuation, and a digest is 64 hexadecimal characters and nothing else.
fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether the argument is a team identifier rather than a code requirement.
///
/// Apple owns both formats, and the two cannot be confused either: a code
/// requirement holds spaces and punctuation, and a team identifier is one
/// alphanumeric token. A digest is alphanumeric as well, so the caller tests
/// that shape first.
fn is_team(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// The bytes of one hexadecimal digest.
fn digest_bytes(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let raw = text.as_bytes();
    for pair in raw.chunks(2) {
        let Ok(text) = core::str::from_utf8(pair) else {
            return Err("the digest is not text".into());
        };
        bytes.push(u8::from_str_radix(text, 16)?);
    }
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = fidelity::new().integrity(Action::Deny, SignalStrength::Medium);

    if let Some(stated) = std::env::args().nth(1) {
        println!("expected identity: {stated}");
        let expected = if is_digest(&stated) {
            let bytes = digest_bytes(&stated)?;
            ExpectedIdentity::new()
                .linux(Choice::Value(ContentDigest::new(bytes)?))
                .windows(Choice::Value(AuthenticodeThumbprint::from_hex(&stated)?))
                .macos(Choice::AcceptUnsupported)
                .ios(Choice::AcceptUnsupported)
                .android(Choice::AcceptUnsupported)
        } else if is_team(&stated) {
            ExpectedIdentity::new()
                .ios(Choice::Value(TeamIdentifier::new(stated)?))
                .macos(Choice::AcceptUnsupported)
                .windows(Choice::AcceptUnsupported)
                .android(Choice::AcceptUnsupported)
                .linux(Choice::AcceptUnsupported)
        } else {
            ExpectedIdentity::new()
                .macos(Choice::Value(CodeRequirement::new(stated)?))
                .ios(Choice::AcceptUnsupported)
                .windows(Choice::AcceptUnsupported)
                .android(Choice::AcceptUnsupported)
                .linux(Choice::AcceptUnsupported)
        };
        builder = builder.expected_identity(expected);
    } else {
        println!("expected identity: none, so that check reports Unsupported");
    }

    let handle = builder.start()?;

    for state in handle.snapshot().detectors() {
        let name = state.detector().name();
        match state.outcome() {
            Outcome::NotRun => println!("  {name}: no scan reached it"),
            Outcome::Clean => println!("  {name}: clean"),
            Outcome::Unsupported { reason } => println!("  {name}: unsupported, {reason}"),
            Outcome::Finding(finding) => println!(
                "  {name}: {:?}, {:?}",
                finding.strength(),
                finding.evidence()
            ),
        }
    }

    match handle.ensure_allowed() {
        Ok(()) => println!("protected operation: allowed"),
        Err(denial) => println!("protected operation: denied, {denial}"),
    }
    Ok(())
}
