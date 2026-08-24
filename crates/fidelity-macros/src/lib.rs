//! The `guarded!()` macro.
//!
//! The macro expands where the host's call sites are, which is why it is a
//! separate crate. It encrypts the host literal at build time, and it emits
//! the decryption at the call site. The plaintext never reaches the binary.
//!
//! This crate is an internal implementation detail of Fidelity. Use it through
//! the `fidelity` crate, which re-exports the macro.

#![forbid(unsafe_code)]

use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

mod literal;

/// The per-build seed. Every build must state one.
const SEED: &str = "FIDELITY_BUILD_SEED";

/// The code identity that this build binds to, or the word that accepts none.
///
/// [`fidelity_cipher::binding`] states the form, because `fidelity/build.rs`
/// reads the same variable and the two must agree about one value.
const IDENTITY: &str = "FIDELITY_CODE_IDENTITY";

/// Guards a host literal against the build and the running code identity.
///
/// ```ignore
/// let host = fidelity::guarded!(&handle, "api.example.com");
/// ```
///
/// The macro takes a reference to a started `Handle` and a string literal. It
/// returns a `Secret<N>` that derefs to `str` and wipes its buffer on drop.
///
/// The build fails when the literal is shorter than eight bytes, when it holds
/// a character outside printable ASCII, when the build states no seed and no
/// identity choice, or when the identity value names no kind of material. Each
/// rule fails the build rather than the run, because a guarded read reports no
/// error at run time by design.
#[proc_macro]
pub fn guarded(input: TokenStream) -> TokenStream {
    match expand(input, LiteralKind::Text) {
        Ok(stream) => stream,
        Err(message) => error(&message),
    }
}

/// Guards a byte-string literal against the build and code identity.
#[proc_macro]
pub fn guarded_bytes(input: TokenStream) -> TokenStream {
    match expand(input, LiteralKind::Bytes) {
        Ok(stream) => stream,
        Err(message) => error(&message),
    }
}

#[derive(Clone, Copy)]
enum LiteralKind {
    Text,
    Bytes,
}

/// Builds the expansion, or the reason that it cannot.
fn expand(input: TokenStream, kind: LiteralKind) -> Result<TokenStream, String> {
    let (handle, literal) = split(input, kind)?;
    let plain = match kind {
        LiteralKind::Text => literal::parse(&literal)?,
        LiteralKind::Bytes => literal::parse_bytes(&literal)?,
    };

    if plain.len() < fidelity_cipher::MIN_BYTES {
        return Err(format!(
            "a guarded literal needs {} bytes or more, and this one has {}. A short value \
             leaves an attacker few possibilities to try",
            fidelity_cipher::MIN_BYTES,
            plain.len()
        ));
    }
    if matches!(kind, LiteralKind::Text) && !fidelity_cipher::in_alphabet(&plain) {
        return Err(String::from(
            "a guarded literal holds printable ASCII only. The stream stays inside that \
             alphabet, so that a wrong key gives a wrong value instead of a decode failure, \
             and a decode failure would tell an attacker that the key is wrong",
        ));
    }

    let seed = std::env::var(SEED).map_err(|_| {
        format!(
            "set {SEED} to a value that this build owns. Two builds with two seeds carry two \
             different guarded values, so one extractor cannot defeat both. A default seed \
             would give every host the same one"
        )
    })?;
    // An unset variable reads as an empty value, and the parser refuses that
    // with the message that also lists the accepted forms.
    let stated = std::env::var(IDENTITY).unwrap_or_default();
    let binding = fidelity_cipher::binding::parse(&stated)
        .map_err(|reason| format!("{IDENTITY} states no usable value: {reason}"))?;

    // The material is the value alone. The kind stays out of the derivation,
    // because the running image reports the value and never the kind.
    let (bound, material): (bool, &[u8]) = match binding {
        fidelity_cipher::binding::Binding::Absent => (false, &[]),
        fidelity_cipher::binding::Binding::Present { value, .. } => (true, value.as_bytes()),
    };

    let salt = fidelity_cipher::derive_salt(seed.as_bytes(), &plain);
    let key = fidelity_cipher::derive_key(&salt, material);
    let value = match kind {
        LiteralKind::Text => fidelity_cipher::encrypt(&key, &plain),
        LiteralKind::Bytes => fidelity_cipher::encrypt_bytes(&key, &plain),
    };

    Ok(assemble(&handle, &salt, &value, bound, kind))
}

/// Writes the tokens that replace the call.
fn assemble(
    handle: &TokenStream,
    salt: &[u8; 16],
    value: &[u8],
    bound: bool,
    kind: LiteralKind,
) -> TokenStream {
    let reader = match kind {
        LiteralKind::Text => "__guarded",
        LiteralKind::Bytes => "__guarded_bytes",
    };
    let body = format!(
        "{{ const __FIDELITY_SALT: [u8; 16] = {}; \
           const __FIDELITY_VALUE: [u8; {}] = {}; \
           ::fidelity::{reader}::<{}, {bound}>(__FIDELITY_HANDLE, \
               &__FIDELITY_SALT, &__FIDELITY_VALUE) }}",
        array(salt),
        value.len(),
        array(value),
        value.len(),
    );

    // The handle expression is host code, so it stays as the caller wrote it.
    // A `let` binds it once, which stops a repeated side effect.
    let mut stream = TokenStream::new();
    stream.extend(
        "let __FIDELITY_HANDLE = "
            .parse::<TokenStream>()
            .unwrap_or_default(),
    );
    stream.extend(handle.clone());
    stream.extend("; ".parse::<TokenStream>().unwrap_or_default());
    stream.extend(body.parse::<TokenStream>().unwrap_or_default());

    TokenStream::from(TokenTree::Group(Group::new(Delimiter::Brace, stream)))
}

/// Formats bytes as a Rust array literal.
fn array(bytes: &[u8]) -> String {
    use core::fmt::Write;

    let mut text = String::from("[");
    for byte in bytes {
        let _ = write!(text, "{byte},");
    }
    text.push(']');
    text
}

/// Splits the input at the top-level comma.
///
/// A group counts as one token tree, so a comma inside brackets never reaches
/// this loop and no depth count is needed.
fn split(input: TokenStream, kind: LiteralKind) -> Result<(TokenStream, String), String> {
    let mut handle = TokenStream::new();
    let mut tail = Vec::new();
    let mut seen_comma = false;
    let (name, literal_name) = match kind {
        LiteralKind::Text => ("guarded!()", "string literal"),
        LiteralKind::Bytes => ("guarded_bytes!()", "byte-string literal"),
    };

    for tree in input {
        match &tree {
            TokenTree::Punct(punct) if punct.as_char() == ',' && !seen_comma => {
                seen_comma = true;
            }
            _ if seen_comma => tail.push(tree),
            _ => handle.extend(TokenStream::from(tree)),
        }
    }

    if !seen_comma {
        return Err(format!(
            "{name} takes a handle and a {literal_name}, separated by a comma"
        ));
    }
    if handle.is_empty() {
        return Err(format!("{name} needs a handle before the literal"));
    }
    match tail.as_slice() {
        [TokenTree::Literal(literal)] => Ok((handle, literal.to_string())),
        [] => Err(format!("{name} needs a {literal_name} after the handle")),
        _ => Err(format!(
            "{name} takes one {literal_name}, and it must be written in place. A constant or a \
             variable would put the plaintext in the binary"
        )),
    }
}

/// Turns a message into a compile error at the call site.
///
/// The expansion carries no semicolon, so it stays an expression. A statement
/// would add a second, confusing error about the tokens that follow.
fn error(message: &str) -> TokenStream {
    format!("compile_error!({message:?})")
        .parse()
        .unwrap_or_default()
}
