//! What a build states about code identity, and which target can carry it.
//!
//! The build side takes the material from this module, and the runtime side
//! takes the same material from the probe. The two must agree, and nothing at
//! run time can report a disagreement: a guarded read has no error path by
//! design, so a wrong material gives a wrong value in silence.
//!
//! Each platform reports a different kind of material, and the variable used
//! to carry a bare value. A value that one target reports therefore reached
//! the key derivation of another target, and every guarded constant in that
//! build decrypted to a wrong value. The value now names its kind, so the
//! build fails instead.
//!
//! Two crates read the variable. `fidelity/build.rs` states whether the build
//! binds at all, and `fidelity-macros` encrypts each literal. Both call this
//! module, so the two can never disagree about one value.

/// The value that states a build which binds to no code identity.
pub const NO_IDENTITY: &str = "none";

/// The character that separates the material kind from the material.
const SEPARATOR: char = ':';

/// The kind of identity material that an operating system reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Material {
    /// The team identifier. macOS and iOS both report it, so one value serves
    /// both targets.
    AppleTeam,

    /// The Authenticode signer certificate digest.
    WindowsCertificate,

    /// The signing certificate digest, as 64 lowercase hexadecimal digits.
    /// Android reports it.
    AndroidCertificate,
}

/// Every kind, in the order that an error message names them.
const EVERY: [Material; 3] = [
    Material::AppleTeam,
    Material::WindowsCertificate,
    Material::AndroidCertificate,
];

impl Material {
    /// The word that names this kind in the identity value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AppleTeam => "apple",
            Self::WindowsCertificate => "windows",
            Self::AndroidCertificate => "android",
        }
    }

    /// The kind that a target operating system reports.
    ///
    /// The argument is the `target_os` value that Cargo states. Returns `None`
    /// on a target whose probe reports no code identity.
    #[must_use]
    pub fn of_target(target_os: &str) -> Option<Self> {
        match target_os {
            "macos" | "ios" => Some(Self::AppleTeam),
            "windows" => Some(Self::WindowsCertificate),
            "android" => Some(Self::AndroidCertificate),
            _ => None,
        }
    }

    /// Reports why this kind rejects the material, or `None` when it accepts.
    ///
    /// Android reports one exact form, so the check is exact. Apple reports a
    /// team identifier, and this project has not verified which characters
    /// that alphabet holds, so the check rejects only what is certainly wrong.
    fn refuses(self, value: &str) -> Option<String> {
        match self {
            Self::AppleTeam => {
                let bad = value
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control());
                bad.then(|| String::from("an Apple team identifier holds no space"))
            }
            Self::WindowsCertificate | Self::AndroidCertificate => {
                let digits = value.len() == 64
                    && value.chars().all(|character| {
                        character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                    });
                (!digits).then(|| {
                    format!(
                        "a signing certificate digest is 64 lowercase hexadecimal digits, and \
                         this one has {}. Use the SHA-256 digest, with no separator",
                        value.len()
                    )
                })
            }
        }
    }
}

/// What one build states about code identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding<'a> {
    /// The build binds to no code identity.
    Absent,

    /// The build binds to the material that it names.
    Present {
        /// The kind of material.
        material: Material,

        /// The material itself, which the running image must report.
        value: &'a str,
    },
}

/// Reads what a build stated in the identity variable.
///
/// # Errors
///
/// Returns the reason that a build cannot use the value. Every reason names
/// the answer, because the caller shows it to a host that is holding a broken
/// build.
pub fn parse(stated: &str) -> Result<Binding<'_>, String> {
    if stated == NO_IDENTITY {
        return Ok(Binding::Absent);
    }

    let Some((name, value)) = stated.split_once(SEPARATOR) else {
        return Err(format!("{}. {}", unnamed(stated), accepted()));
    };
    let Some(material) = EVERY.into_iter().find(|kind| kind.name() == name) else {
        return Err(format!(
            "the identity value names the kind \"{name}\", which no platform reports. {}",
            accepted()
        ));
    };
    if value.is_empty() {
        return Err(format!(
            "the identity value names the kind \"{name}\" and no material after it"
        ));
    }
    if let Some(reason) = material.refuses(value) {
        return Err(format!("the identity value is not usable: {reason}"));
    }

    Ok(Binding::Present { material, value })
}

/// Reports whether a target reports the material that a build names.
///
/// # Errors
///
/// Returns the reason that this target cannot carry the material. One Cargo
/// invocation builds one target, so a second target is a second invocation
/// with the value that it reports.
pub fn check_target(material: Material, target_os: &str) -> Result<(), String> {
    match Material::of_target(target_os) {
        Some(reported) if reported == material => Ok(()),
        Some(reported) => Err(format!(
            "the build names {} material, and the target \"{target_os}\" reports {} material. \
             The key derivation would take material that the running image never reports, and \
             every guarded constant would decrypt to a wrong value with no error",
            material.name(),
            reported.name()
        )),
        None => Err(format!(
            "the build names {} material, and the target \"{target_os}\" reports no code \
             identity at all. Set the identity value to \"{NO_IDENTITY}\" for this target",
            material.name()
        )),
    }
}

/// Why a value that names no kind is refused.
fn unnamed(stated: &str) -> String {
    if stated.is_empty() {
        return String::from("the identity value is empty, and silence states nothing");
    }
    String::from("the identity value names no material kind")
}

/// The forms that a value may take, as one sentence.
fn accepted() -> String {
    let names: Vec<String> = EVERY
        .into_iter()
        .map(|kind| format!("\"{}{SEPARATOR}<value>\"", kind.name()))
        .collect();
    format!(
        "Write {}, or \"{NO_IDENTITY}\" to state that this build binds to no identity",
        names.join(" or ")
    )
}

#[cfg(test)]
mod tests {
    use super::{Binding, Material, NO_IDENTITY, check_target, parse};

    const DIGEST: &str = "9f3a1c0e5b7d2846a09f3a1c0e5b7d2846a09f3a1c0e5b7d2846a09f3a1c0e5b";

    #[test]
    fn the_word_none_binds_a_build_to_nothing() {
        let Ok(binding) = parse(NO_IDENTITY) else {
            panic!("the word that states no binding must parse");
        };
        assert_eq!(binding, Binding::Absent);
    }

    #[test]
    fn an_apple_value_carries_the_team_identifier_alone() {
        let Ok(Binding::Present { material, value }) = parse("apple:ABCDE12345") else {
            panic!("a named apple value must parse");
        };
        assert_eq!((material, value), (Material::AppleTeam, "ABCDE12345"));
    }

    #[test]
    fn an_android_value_carries_the_digest_alone() {
        let stated = format!("android:{DIGEST}");
        let Ok(Binding::Present { material, value }) = parse(&stated) else {
            panic!("a named android value must parse");
        };
        assert_eq!((material, value), (Material::AndroidCertificate, DIGEST));
    }

    #[test]
    fn a_windows_value_carries_the_digest_alone() {
        let stated = format!("windows:{DIGEST}");
        let Ok(Binding::Present { material, value }) = parse(&stated) else {
            panic!("a named Windows value must parse");
        };
        assert_eq!((material, value), (Material::WindowsCertificate, DIGEST));
    }

    #[test]
    fn a_value_that_names_no_kind_is_refused() {
        // This is the form that every build used before the kind was named,
        // so the message has to say what to write instead.
        let Err(reason) = parse("ABCDE12345") else {
            panic!("a bare value must not parse");
        };
        assert!(reason.contains("apple:<value>"), "{reason}");
    }

    #[test]
    fn a_kind_that_no_platform_reports_is_refused() {
        let Err(reason) = parse("freebsd:ABCDE12345") else {
            panic!("an unknown kind must not parse");
        };
        assert!(reason.contains("\"freebsd\""), "{reason}");
    }

    #[test]
    fn the_digest_form_that_keytool_prints_is_refused() {
        // `keytool -list -v` separates every pair with a colon. The first pair
        // then reads as the kind, so this has to fail on the kind and not on
        // the length.
        let printed = "9F:3A:1C:0E:5B:7D:28:46";
        let Err(reason) = parse(printed) else {
            panic!("the printed digest form must not parse");
        };
        assert!(reason.contains("\"9F\""), "{reason}");
    }

    #[test]
    fn a_sha1_digest_in_place_of_a_sha256_digest_is_refused() {
        // `keytool` prints both, one line apart, and the shorter one is the
        // easier line to copy.
        let sha1 = "9f3a1c0e5b7d2846a09f3a1c0e5b7d2846a09f3a";
        let Err(reason) = parse(&format!("android:{sha1}")) else {
            panic!("a digest of the wrong length must not parse");
        };
        assert!(reason.contains("and this one has 40"), "{reason}");
    }

    #[test]
    fn an_uppercase_digest_is_refused() {
        // The probe reports lowercase, so an uppercase build value derives
        // another key and nothing at run time reports it.
        let Err(reason) = parse(&format!("android:{}", DIGEST.to_uppercase())) else {
            panic!("an uppercase digest must not parse");
        };
        assert!(reason.contains("lowercase"), "{reason}");
    }

    #[test]
    fn a_kind_with_no_material_after_it_is_refused() {
        let Err(reason) = parse("apple:") else {
            panic!("a kind with no material must not parse");
        };
        assert!(reason.contains("no material after it"), "{reason}");
    }

    #[test]
    fn one_apple_value_serves_both_apple_targets() {
        assert_eq!(
            Material::of_target("macos"),
            Material::of_target("ios"),
            "macOS and iOS both report the team identifier"
        );
    }

    #[test]
    fn a_target_accepts_the_material_that_it_reports() {
        assert_eq!(check_target(Material::AppleTeam, "macos"), Ok(()));
    }

    #[test]
    fn a_target_refuses_the_material_of_another_platform() {
        // The gap that this module closes. An Apple team identifier in an
        // Android build derived a key that the running image never reproduces.
        let Err(reason) = check_target(Material::AppleTeam, "android") else {
            panic!("an apple value must not build for android");
        };
        assert!(reason.contains("reports android material"), "{reason}");
    }

    #[test]
    fn a_target_without_identity_refuses_every_material() {
        let Err(reason) = check_target(Material::AppleTeam, "linux") else {
            panic!("a bound build must not target a platform without identity");
        };
        assert!(reason.contains("no code identity at all"), "{reason}");
    }
}
