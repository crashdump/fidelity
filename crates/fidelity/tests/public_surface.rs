//! A snapshot of the public surface, so a change to it is a decision.
//!
//! `docs/plan/06-delivery.md` asks the gate to verify public-surface drift, and
//! nothing verified it before this file. The `fidelity` crate is the only
//! `SemVer` surface, and it re-exports the data model from `fidelity-types`, so
//! both crates are here. Every other crate is an internal implementation detail
//! and makes no compatibility promise.
//!
//! The rule fails when the code and the snapshot disagree. An addition updates
//! the snapshot in the same change, and a removal or a rename is a breaking
//! change that the changelog states. Version 0.1.0 is published, so that
//! applies from now on.
//!
//! What this rule does not check. It reads Rust as text, for the reason that
//! `architecture.rs` states: a rule about the shape of the workspace has to see
//! the workspace. It therefore reads a declaration rather than a resolved type.
//! It does not follow a re-export into the crate that owns the item, it does
//! not read a derived trait, and it does not read a generic bound. It reads no
//! `cfg` either, so the optional `serde` surface is here whether or not the
//! feature is on, and the snapshot states one answer for every build.
//!
//! The snapshot is not a list of promises. It holds an item that `#[doc(hidden)]`
//! marks, because `guarded!()` reads one and a removal would break every host
//! that calls the macro. The rustdoc of each item states what it promises. It sees
//! an item that arrives, an item that goes, and a signature that changes shape,
//! and those three are what drift looks like.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The crates that a host names. The snapshot covers these two and no other.
const PUBLIC: &[&str] = &["fidelity", "fidelity-types"];

/// Where the accepted surface lives.
const SNAPSHOT: &str = "crates/fidelity/tests/public-surface.txt";

/// The one macro in the workspace that declares a public item.
///
/// A macro body carries the parameter name rather than the method name, so a
/// reader of the text alone records `$name` and loses all six methods. The
/// extractor expands this one instead, and the rule below proves that the body
/// still generates the signature that the expansion states.
const SETTER: &str = "category_setter!(";

/// What the macro above generates, once for each category.
const SETTER_BODY: &str =
    "pub fn $name(mut self, action: Action, threshold: SignalStrength) -> Self";

/// Items that the surface holds, whatever else changes.
///
/// The extractor skips a test module and a macro body, and an over-skip would
/// drop real items and still leave a file that reads as complete. These four
/// sit in four different files, so an over-skip that reached any of them fails
/// here with a message that names the item it lost.
const ANCHORS: &[&str] = &[
    "fidelity  pub fn new() -> Builder",
    "fidelity::Handle  pub fn ensure_allowed(&self)",
    "fidelity::Builder  pub fn integrity(",
    "fidelity-types::Outcome  variant Unsupported",
];

/// The workspace root, from this crate's manifest.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the workspace root must resolve: {error}"))
}

/// Every Rust file of one directory tree, in a stable order.
fn sources(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return found;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    found
}

/// What kind of declaration a line opens, which decides where it ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A signature, which ends where its parameter list closes.
    Signature,
    /// A re-export, which ends where its brace list closes.
    Export,
    /// A constant, which ends at its semicolon.
    Constant,
    /// A type or a module, which ends on its own line.
    Item,
}

/// The kind of public declaration that a line opens, if it opens one.
///
/// A `pub(crate)` item starts with `pub(`, so no arm below matches it.
fn kind(line: &str) -> Option<Kind> {
    for prefix in ["pub fn ", "pub const fn ", "pub unsafe fn "] {
        if line.starts_with(prefix) {
            return Some(Kind::Signature);
        }
    }
    if line.starts_with("pub use ") {
        return Some(Kind::Export);
    }
    if line.starts_with("pub const ") {
        return Some(Kind::Constant);
    }
    for prefix in [
        "pub struct ",
        "pub enum ",
        "pub trait ",
        "pub type ",
        "pub mod ",
    ] {
        if line.starts_with(prefix) {
            return Some(Kind::Item);
        }
    }
    None
}

/// Whether the text holds more of the opening bracket than the closing one.
fn open(text: &str, opening: char, closing: char) -> bool {
    text.matches(opening).count() > text.matches(closing).count()
}

/// One declaration, with the whitespace collapsed and the noise removed.
fn tidy(text: &str) -> String {
    let joined = text.split_whitespace().collect::<Vec<&str>>().join(" ");
    // A signature that spanned several lines carries the trailing comma that
    // the formatter wrote, and the joined line must read like a short one.
    let joined = joined.replace("( ", "(").replace(", )", ")");
    let joined = joined.replace(" )", ")").replace(",)", ")");
    let joined = joined.trim_end().trim_end_matches(['{', ';']).trim_end();
    joined.to_string()
}

/// The name of the type that an `impl` block covers.
///
/// A trait implementation adds no item of its own, and this snapshot holds no
/// derived trait either, so both forms report the type that carries the block.
fn impl_target(line: &str) -> Option<String> {
    let rest = line.trim_end().strip_suffix('{')?.trim_end();
    let rest = rest.strip_prefix("impl")?;
    // A generic parameter list sits between the keyword and the type, and it
    // holds its own angle brackets, so the skip counts depth.
    let rest = if rest.starts_with('<') {
        let mut depth = 0_i32;
        let mut end = rest.len();
        for (index, character) in rest.char_indices() {
            match character {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        &rest[end..]
    } else {
        rest
    };
    let target = rest.rsplit(" for ").next().unwrap_or(rest).trim();
    let target = target.split(['<', ' ']).next().unwrap_or(target);
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

/// The name of one enum variant, from the body of a public enum.
fn variant(line: &str) -> Option<&str> {
    let name = line.split(['(', '{', ',', ' ']).next()?;
    let mut characters = name.chars();
    if !characters.next().is_some_and(char::is_uppercase) {
        return None;
    }
    if characters.any(|character| !character.is_alphanumeric() && character != '_') {
        return None;
    }
    Some(name)
}

/// Reads one crate and adds every public item that it declares.
fn collect(krate: &str, text: &str, items: &mut BTreeSet<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut skipping = false;
    let mut context: Option<String> = None;
    let mut open_enum: Option<String> = None;
    let mut index = 0;
    while index < lines.len() {
        let raw = lines[index];
        index += 1;
        // A block that a test module, a macro, or a top-level item opened ends
        // here, and so does every context that it set.
        if raw == "}" {
            skipping = false;
            context = None;
            open_enum = None;
            continue;
        }
        if skipping {
            continue;
        }
        let line = raw.trim();
        if line == "#[cfg(test)]" || line.starts_with("macro_rules!") {
            skipping = true;
            continue;
        }
        if line.starts_with("//") {
            continue;
        }
        if let Some(name) = open_enum.clone() {
            if let Some(found) = variant(line) {
                items.insert(format!("{krate}::{name}  variant {found}"));
            }
            continue;
        }
        if raw.starts_with("impl") {
            context = impl_target(line);
            continue;
        }
        let path = context
            .clone()
            .map_or_else(|| krate.to_string(), |name| format!("{krate}::{name}"));
        if line.starts_with(SETTER) {
            // The invocation names the method, and the body above names the
            // signature. Join until the argument list closes, so an invocation
            // that spans several lines reads the same as a short one.
            let mut call = line.to_string();
            while open(&call, '(', ')') && index < lines.len() {
                call.push(' ');
                call.push_str(lines[index].trim());
                index += 1;
            }
            let name = call
                .trim_start_matches(SETTER)
                .split(',')
                .next()
                .unwrap_or_default()
                .trim();
            items.insert(format!("{path}  {}", SETTER_BODY.replace("$name", name)));
            continue;
        }
        let Some(shape) = kind(line) else {
            continue;
        };
        let mut declaration = line.to_string();
        loop {
            let more = match shape {
                Kind::Signature => open(&declaration, '(', ')'),
                Kind::Export => open(&declaration, '{', '}'),
                Kind::Constant => !declaration.trim_end().ends_with(';'),
                Kind::Item => false,
            };
            if !more || index >= lines.len() {
                break;
            }
            declaration.push(' ');
            declaration.push_str(lines[index].trim());
            index += 1;
        }
        let declaration = tidy(&declaration);
        if let Some(name) = declaration.strip_prefix("pub enum ") {
            let name = name.split('<').next().unwrap_or(name);
            open_enum = Some(name.to_string());
        }
        items.insert(format!("{path}  {declaration}"));
    }
}

/// The surface that the code declares today.
fn surface() -> Vec<String> {
    let mut items = BTreeSet::new();
    for krate in PUBLIC {
        let directory = root().join("crates").join(krate).join("src");
        for path in sources(&directory) {
            let Ok(text) = fs::read_to_string(&path) else {
                panic!("{} must read", path.display());
            };
            collect(krate, &text, &mut items);
        }
    }
    items.into_iter().collect()
}

#[test]
fn the_setter_macro_still_generates_the_signature_that_the_snapshot_expands() {
    // The extractor expands one macro by hand, so it holds a copy of what that
    // macro writes. This rule is what stops the copy from drifting: a change to
    // the body fails here, and the message says which line to update.
    let path = root().join("crates/fidelity/src/builder.rs");
    let Ok(text) = fs::read_to_string(&path) else {
        panic!("crates/fidelity/src/builder.rs must read");
    };
    assert!(
        text.contains(SETTER_BODY),
        "the {SETTER} body changed, so update SETTER_BODY in this file to match it"
    );
}

#[test]
fn the_public_surface_matches_the_accepted_snapshot() {
    let found = surface();
    for anchor in ANCHORS {
        assert!(
            found.iter().any(|item| item.starts_with(anchor)),
            "the extractor found no {anchor}, so it read less than the crate declares"
        );
    }
    // A macro parameter is not a method name. One reached the snapshot before
    // the extractor expanded the macro, and it hid all six category setters.
    for item in &found {
        assert!(
            !item.contains('$'),
            "{item} names a macro parameter, so a generator macro is unexpanded"
        );
    }

    let path = root().join(SNAPSHOT);
    let Ok(accepted) = fs::read_to_string(&path) else {
        panic!("{SNAPSHOT} must exist, and it holds the accepted surface");
    };
    let accepted: Vec<&str> = accepted.lines().filter(|line| !line.is_empty()).collect();

    let arrived: Vec<&String> = found
        .iter()
        .filter(|item| !accepted.contains(&item.as_str()))
        .collect();
    let gone: Vec<&&str> = accepted
        .iter()
        .filter(|item| !found.iter().any(|found| found == *item))
        .collect();
    if arrived.is_empty() && gone.is_empty() {
        return;
    }

    // The failure has to be actionable, so write what the code says next to the
    // file that holds what the project accepted.
    let fresh = root().join("target/public-surface.txt");
    let mut body = found.join("\n");
    body.push('\n');
    let written = fs::write(&fresh, &body).is_ok();
    panic!(
        "the public surface moved.\n  arrived: {arrived:#?}\n  gone: {gone:#?}\n\
         An addition updates {SNAPSHOT}. A removal or a rename is a breaking change,\n\
         and the changelog states it. Accept the new surface with:\n\
         cp target/public-surface.txt {SNAPSHOT}\n\
         (that file {} written)",
        if written { "was" } else { "was not" }
    );
}

#[test]
fn runtime_read_types_are_send_and_sync() {
    fn require<T: Send + Sync + 'static>() {}

    require::<fidelity::Handle>();
    require::<fidelity::Snapshot>();
    require::<fidelity::Denied>();
    require::<fidelity::Finding>();
    require::<fidelity::DetectorState>();
}
