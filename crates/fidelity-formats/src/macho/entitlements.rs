//! The reader for the entitlements of a signed Apple image.
//!
//! The entitlements slot holds an XML plist. This reader takes the one value
//! that identity needs, and it parses no more of the format than that. A
//! general plist reader would be a much larger surface for one string.
//!
//! Two keys carry the team. `com.apple.developer.team-identifier` states it
//! directly. `application-identifier` states the App ID, whose prefix is the
//! team, and `docs/plan/04-detectors-and-platforms.md` names that one for iOS.
//! The direct key wins where both are present, because it needs no split.

/// The key that states the team identifier on its own.
const TEAM_KEY: &str = "com.apple.developer.team-identifier";

/// The key that states the App ID, whose prefix is the team identifier.
const APP_ID_KEY: &str = "application-identifier";

/// The longest team identifier that this reader accepts from the direct key.
///
/// That key states the team and nothing else, so the value needs no split and
/// the bound only stops a malformed plist from producing a long value.
const MAX_TEAM: usize = 64;

/// The length of the team identifier that Apple issues.
///
/// The App ID prefix needs this, and the direct key does not. Splitting an App
/// ID at its first full stop is a guess: `com.example.app` splits into a
/// three-character prefix that reads as a team and is not one. The prefix
/// therefore counts only at the length Apple issues. A value of another length
/// reports no team, which is a gap, and never a wrong team.
const TEAM_LENGTH: usize = 10;

/// Reads the team identifier out of an entitlements plist.
///
/// Returns `None` when neither key is present, when the value is empty, or
/// when the text is not the plist that a signed image carries. An image with
/// no team is the common `None`: Cargo signs a local build ad hoc, and an
/// ad-hoc signature names no team.
///
/// The caller never turns `None` into a clean result. It reports the gap.
#[must_use]
pub fn team_identifier(plist: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(plist).ok()?;

    if let Some(team) = string_value(text, TEAM_KEY).filter(|team| acceptable(team)) {
        return Some(team);
    }

    // The App ID is the team, a full stop, then the bundle identifier. A value
    // with no full stop states no team, so it never reads as one.
    let app_id = string_value(text, APP_ID_KEY)?;
    let (team, bundle) = app_id.split_once('.')?;
    if bundle.is_empty() || team.len() != TEAM_LENGTH || !acceptable(team) {
        return None;
    }
    Some(team)
}

/// Reports whether a candidate reads as a team identifier.
///
/// Apple issues an alphanumeric value. The check rejects anything else, so a
/// malformed plist never reaches the key derivation of a guarded constant.
fn acceptable(team: &str) -> bool {
    !team.is_empty()
        && team.len() <= MAX_TEAM
        && team
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// Reads the string that follows one key in an XML plist.
///
/// The format writes `<key>name</key>` and then the value element. The reader
/// takes the text between the next `<string>` and `</string>`, and it stops at
/// the first key that matches.
fn string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut rest = text;

    // A key that another key ends with must not match, so each candidate is
    // checked against the whole element. `com.apple.application-identifier`
    // ends with `application-identifier`, and the two are different keys.
    loop {
        let at = rest.find("<key>")?;
        let after = rest.get(at + "<key>".len()..)?;
        let (name, tail) = after.split_once("</key>")?;
        if name.trim() == key {
            let (_, value) = tail.split_once("<string>")?;
            let (value, _) = value.split_once("</string>")?;
            return Some(value.trim());
        }
        rest = tail;
    }
}

#[cfg(test)]
mod tests {
    use super::team_identifier;
    use crate::macho::signature::entitlements;

    /// A real ad-hoc signature that carries a team-prefixed application
    /// identifier. `tests/platform/controls/entitle.c` made it.
    const WITH_TEAM: &[u8] = include_bytes!("../fixtures/macho-signature-team.bin");

    /// The entitlements of the recorded ad-hoc signature.
    ///
    /// The two readers meet here, so this is where a recorded image proves the
    /// whole parse and not one half of it.
    fn recorded() -> &'static [u8] {
        let Some(plist) = entitlements(WITH_TEAM) else {
            panic!("the fixture carries entitlements")
        };
        plist
    }

    #[test]
    fn the_recorded_image_reports_the_team_that_signed_it() {
        assert_eq!(team_identifier(recorded()), Some("ABCDE12345"));
    }

    #[test]
    fn the_direct_key_wins_over_the_app_identifier() {
        // A real profile carries both, and the two agree. The direct key needs
        // no split, so it answers first.
        let plist = b"<key>application-identifier</key><string>WRONG00000.app</string>\
                      <key>com.apple.developer.team-identifier</key><string>RIGHT12345</string>";
        assert_eq!(team_identifier(plist), Some("RIGHT12345"));
    }

    #[test]
    fn an_app_identifier_alone_reports_its_prefix() {
        let plist = b"<key>application-identifier</key><string>ABCDE12345.com.example.app</string>";
        assert_eq!(team_identifier(plist), Some("ABCDE12345"));
    }

    #[test]
    fn a_key_that_another_key_ends_with_never_matches() {
        // Apple signs its own applications with `com.apple.application-\
        // identifier`, which ends with the key this reader wants. A search for
        // a fragment would read the wrong element, and Apple's value carries
        // no team at all.
        let plist = b"<key>com.apple.application-identifier</key><string>com.apple.Notes</string>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn an_app_identifier_with_no_bundle_reports_nothing() {
        let plist = b"<key>application-identifier</key><string>ABCDE12345.</string>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn an_app_identifier_with_no_team_reports_nothing() {
        // The split is a guess, and this value would give a three-character
        // prefix that reads as a team. Only the length Apple issues counts.
        let plist = b"<key>application-identifier</key><string>com.example.app</string>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn the_direct_key_needs_no_length_that_apple_issues() {
        // That key states the team and nothing else, so there is no guess to
        // constrain. A length rule there would drop a real identity.
        let plist = b"<key>com.apple.developer.team-identifier</key><string>SHORT</string>";
        assert_eq!(team_identifier(plist), Some("SHORT"));
    }

    #[test]
    fn a_team_outside_the_alphabet_reports_nothing() {
        // The value derives the key of a guarded constant, so a malformed one
        // must never reach it.
        let plist = b"<key>com.apple.developer.team-identifier</key><string>../../etc</string>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn an_empty_team_reports_nothing() {
        let plist = b"<key>com.apple.developer.team-identifier</key><string></string>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn a_plist_without_either_key_reports_nothing() {
        let plist = b"<key>com.apple.security.get-task-allow</key><true/>";
        assert_eq!(team_identifier(plist), None);
    }

    #[test]
    fn text_that_is_not_a_plist_reports_nothing() {
        assert_eq!(team_identifier(b"not a plist"), None);
    }

    #[test]
    fn bytes_that_are_not_text_report_nothing() {
        assert_eq!(team_identifier(&[0xff, 0xfe, 0x00]), None);
    }

    #[test]
    fn empty_bytes_report_nothing() {
        assert_eq!(team_identifier(&[]), None);
    }
}
