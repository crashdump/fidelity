//! Reads the bytes of a Rust string literal.
//!
//! The macro takes no dependency, so it reads the literal itself. Only the
//! escapes that can produce a printable character are accepted. Every other
//! escape produces a character outside the alphabet, so rejecting it here
//! gives a clearer message than the alphabet check would.

/// The bytes that a string literal holds.
///
/// # Errors
///
/// Returns a message when the token is not a string literal, or when it holds
/// an escape that a guarded value cannot carry.
pub(crate) fn parse(token: &str) -> Result<Vec<u8>, String> {
    if let Some(body) = raw_body(token) {
        return Ok(body.as_bytes().to_vec());
    }

    let body = token
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| format!("guarded!() takes a string literal, and it received {token}"))?;

    let mut bytes = Vec::with_capacity(body.len());
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            let mut buffer = [0_u8; 4];
            bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            continue;
        }

        match characters.next() {
            Some('\\') => bytes.push(b'\\'),
            Some('"') => bytes.push(b'"'),
            Some('\'') => bytes.push(b'\''),
            Some('x') => {
                let high = characters.next().unwrap_or('_');
                let low = characters.next().unwrap_or('_');
                let value = u8::from_str_radix(&format!("{high}{low}"), 16)
                    .map_err(|_| format!("the escape \\x{high}{low} is not a byte"))?;
                bytes.push(value);
            }
            Some(other) => {
                return Err(format!(
                    "a guarded literal cannot carry the escape \\{other}, because it leaves \
                     printable ASCII"
                ));
            }
            None => return Err(String::from("the literal ends inside an escape")),
        }
    }
    Ok(bytes)
}

/// The bytes that a byte-string literal holds.
///
/// # Errors
///
/// Returns a message when the token is not a byte-string literal, or when it
/// holds an invalid byte escape.
pub(crate) fn parse_bytes(token: &str) -> Result<Vec<u8>, String> {
    if let Some(body) = raw_byte_body(token) {
        if !body.is_ascii() {
            return Err(String::from(
                "a byte-string literal holds ASCII or byte escapes",
            ));
        }
        return Ok(body.as_bytes().to_vec());
    }

    let body = token
        .strip_prefix("b\"")
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| {
            format!("guarded_bytes!() takes a byte-string literal, and it received {token}")
        })?;

    let mut bytes = Vec::with_capacity(body.len());
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            if !character.is_ascii() {
                return Err(String::from(
                    "a byte-string literal holds ASCII or byte escapes",
                ));
            }
            bytes.push(character as u8);
            continue;
        }

        match characters.next() {
            Some('\\') => bytes.push(b'\\'),
            Some('"') => bytes.push(b'"'),
            Some('n') => bytes.push(b'\n'),
            Some('r') => bytes.push(b'\r'),
            Some('t') => bytes.push(b'\t'),
            Some('0') => bytes.push(0),
            Some('x') => {
                let high = characters.next().unwrap_or('_');
                let low = characters.next().unwrap_or('_');
                let value = u8::from_str_radix(&format!("{high}{low}"), 16)
                    .map_err(|_| format!("the escape \\x{high}{low} is not a byte"))?;
                bytes.push(value);
            }
            Some(other) => {
                return Err(format!("the byte-string escape \\{other} is invalid"));
            }
            None => {
                return Err(String::from(
                    "the byte-string literal ends inside an escape",
                ));
            }
        }
    }
    Ok(bytes)
}

/// The body of a raw string literal, when the token is one.
fn raw_body(token: &str) -> Option<&str> {
    let rest = token.strip_prefix('r')?;
    let hashes = rest.len() - rest.trim_start_matches('#').len();
    let opened = rest.strip_prefix(&"#".repeat(hashes))?;
    let body = opened.strip_prefix('"')?;
    body.strip_suffix(&format!("\"{}", "#".repeat(hashes)))
}

/// The body of a raw byte-string literal, when the token is one.
fn raw_byte_body(token: &str) -> Option<&str> {
    let rest = token.strip_prefix("br")?;
    let hashes = rest.len() - rest.trim_start_matches('#').len();
    let opened = rest.strip_prefix(&"#".repeat(hashes))?;
    let body = opened.strip_prefix('"')?;
    body.strip_suffix(&format!("\"{}", "#".repeat(hashes)))
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_bytes};

    #[test]
    fn a_plain_literal_reads_back() {
        assert_eq!(
            parse("\"api.example.com\""),
            Ok(b"api.example.com".to_vec())
        );
    }

    #[test]
    fn an_escaped_quote_reads_back() {
        assert_eq!(parse("\"a\\\"b\""), Ok(b"a\"b".to_vec()));
    }

    #[test]
    fn an_escaped_backslash_reads_back() {
        assert_eq!(parse("\"a\\\\b\""), Ok(b"a\\b".to_vec()));
    }

    #[test]
    fn a_byte_escape_reads_back() {
        assert_eq!(parse("\"a\\x41b\""), Ok(b"aAb".to_vec()));
    }

    #[test]
    fn a_raw_literal_reads_back() {
        assert_eq!(parse("r\"a\\b\""), Ok(b"a\\b".to_vec()));
    }

    #[test]
    fn a_hashed_raw_literal_reads_back() {
        assert_eq!(parse("r#\"a\"b\"#"), Ok(b"a\"b".to_vec()));
    }

    #[test]
    fn a_newline_escape_reports_the_alphabet() {
        let message = parse("\"a\\nb\"").err().unwrap_or_default();
        assert!(message.contains("printable ASCII"), "{message}");
    }

    #[test]
    fn a_number_is_not_a_string_literal() {
        assert!(parse("42").is_err());
    }

    #[test]
    fn a_byte_string_keeps_arbitrary_bytes() {
        assert_eq!(
            parse_bytes("b\"a\\x00\\xffz\""),
            Ok(vec![b'a', 0, 0xff, b'z'])
        );
    }

    #[test]
    fn a_raw_byte_string_keeps_its_backslash() {
        assert_eq!(parse_bytes("br\"a\\b\""), Ok(b"a\\b".to_vec()));
    }

    #[test]
    fn a_string_is_not_a_byte_string() {
        assert!(parse_bytes("\"plain\"").is_err());
    }
}
