use core::fmt;

/// A target platform that Fidelity supports.
///
/// The enumeration is `#[non_exhaustive]`, because the supported set may grow
/// after v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Platform {
    /// Windows on ARM64 or `x86_64`.
    Windows,
    /// macOS on ARM64 or `x86_64`.
    MacOs,
    /// iOS on ARM64, plus the supported simulators.
    Ios,
    /// Android on ARM64, plus the supported emulators.
    Android,
    /// glibc Linux on ARM64 or `x86_64`.
    Linux,
}

impl Platform {
    /// The platform that this build targets.
    ///
    /// Returns `None` on a target outside the supported set.
    #[must_use]
    pub const fn target() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "ios") {
            Some(Self::Ios)
        } else if cfg!(target_os = "android") {
            Some(Self::Android)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// What the host decides about expected identity on one platform.
///
/// Expected identity is optional as a whole. A host that supplies nothing
/// gets an `Unsupported` outcome with a stated reason, and the runtime
/// baseline still runs. A host that calls the builder setter makes the check
/// required, and must then state a choice for every platform it ships to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Choice<T> {
    /// Fidelity compares the running image against this value.
    Value(T),

    /// The host accepts that this platform reports `Unsupported`.
    ///
    /// This states a deliberate gap, such as a Linux deployment without
    /// fs-verity. Silence states nothing, and silence fails the start.
    AcceptUnsupported,
}

/// The identity values that the host supplies, for every target at once.
///
/// One value covers every platform, so a single configuration
/// cross-compiles. Fidelity never learns these values from the running bytes
/// it verifies, and it ships no tool to produce them. The host obtains them
/// from its own signing and build pipeline.
///
/// # Examples
///
/// ```
/// use fidelity_types::{Choice, ExpectedIdentity, TeamIdentifier};
///
/// let team = TeamIdentifier::new("ABCDE12345")?;
/// let identity = ExpectedIdentity::new()
///     .ios(Choice::Value(team))
///     // This deployment ships without fs-verity, and says so.
///     .linux(Choice::AcceptUnsupported);
/// # Ok::<(), fidelity_types::IdentityError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedIdentity {
    windows: Option<Choice<AuthenticodeThumbprint>>,
    macos: Option<Choice<CodeRequirement>>,
    ios: Option<Choice<TeamIdentifier>>,
    android: Option<Choice<CertificateSha256>>,
    linux: Option<Choice<ContentDigest>>,
}

impl ExpectedIdentity {
    /// Creates a value with no choice stated for any platform.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            windows: None,
            macos: None,
            ios: None,
            android: None,
            linux: None,
        }
    }

    /// States the choice for Windows, as an Authenticode signer thumbprint.
    #[must_use]
    pub fn windows(mut self, choice: Choice<AuthenticodeThumbprint>) -> Self {
        self.windows = Some(choice);
        self
    }

    /// States the choice for macOS, as a code requirement string.
    #[must_use]
    pub fn macos(mut self, choice: Choice<CodeRequirement>) -> Self {
        self.macos = Some(choice);
        self
    }

    /// States the choice for iOS, as a team identifier.
    #[must_use]
    pub fn ios(mut self, choice: Choice<TeamIdentifier>) -> Self {
        self.ios = Some(choice);
        self
    }

    /// States the choice for Android, as a signing certificate digest.
    ///
    /// The value is the distribution signing certificate. It is not the
    /// upload certificate when Play App Signing is in use.
    #[must_use]
    pub fn android(mut self, choice: Choice<CertificateSha256>) -> Self {
        self.android = Some(choice);
        self
    }

    /// States the choice for Linux, as a content digest.
    #[must_use]
    pub fn linux(mut self, choice: Choice<ContentDigest>) -> Self {
        self.linux = Some(choice);
        self
    }

    /// The choice that the host stated for Windows.
    #[must_use]
    pub const fn windows_choice(&self) -> Option<&Choice<AuthenticodeThumbprint>> {
        self.windows.as_ref()
    }

    /// The choice that the host stated for macOS.
    #[must_use]
    pub const fn macos_choice(&self) -> Option<&Choice<CodeRequirement>> {
        self.macos.as_ref()
    }

    /// The choice that the host stated for iOS.
    #[must_use]
    pub const fn ios_choice(&self) -> Option<&Choice<TeamIdentifier>> {
        self.ios.as_ref()
    }

    /// The choice that the host stated for Android.
    #[must_use]
    pub const fn android_choice(&self) -> Option<&Choice<CertificateSha256>> {
        self.android.as_ref()
    }

    /// The choice that the host stated for Linux.
    #[must_use]
    pub const fn linux_choice(&self) -> Option<&Choice<ContentDigest>> {
        self.linux.as_ref()
    }

    /// Reports whether the host stated a choice for this platform.
    ///
    /// The start sequence fails with a typed error when the choice for the
    /// target platform is absent.
    #[must_use]
    pub const fn states_choice_for(&self, platform: Platform) -> bool {
        match platform {
            Platform::Windows => self.windows.is_some(),
            Platform::MacOs => self.macos.is_some(),
            Platform::Ios => self.ios.is_some(),
            Platform::Android => self.android.is_some(),
            Platform::Linux => self.linux.is_some(),
        }
    }
}

/// An Authenticode signer thumbprint, as a SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticodeThumbprint([u8; 32]);

impl AuthenticodeThumbprint {
    /// Creates a thumbprint from raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a thumbprint from a 64-character hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not 64 hexadecimal characters.
    pub fn from_hex(hex: &str) -> Result<Self, IdentityError> {
        parse_sha256_hex(hex).map(Self)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Android signing certificate, as a SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateSha256([u8; 32]);

impl CertificateSha256 {
    /// Creates a certificate digest from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a certificate digest from a 64-character hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not 64 hexadecimal characters.
    pub fn from_hex(hex: &str) -> Result<Self, IdentityError> {
        parse_sha256_hex(hex).map(Self)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A macOS code requirement string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeRequirement(String);

impl CodeRequirement {
    /// Creates a code requirement.
    ///
    /// Fidelity checks that the text is present. The operating system parses
    /// the requirement itself, so Fidelity does not validate the grammar.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is empty.
    pub fn new(requirement: impl Into<String>) -> Result<Self, IdentityError> {
        let requirement = requirement.into();
        if requirement.trim().is_empty() {
            return Err(IdentityError::Empty);
        }
        Ok(Self(requirement))
    }

    /// The requirement text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An Apple team identifier, read from the App ID prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TeamIdentifier(String);

impl TeamIdentifier {
    /// Creates a team identifier.
    ///
    /// Fidelity checks that the text is present. Apple owns the format, so
    /// Fidelity does not validate it further.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is empty.
    pub fn new(identifier: impl Into<String>) -> Result<Self, IdentityError> {
        let identifier = identifier.into();
        if identifier.trim().is_empty() {
            return Err(IdentityError::Empty);
        }
        Ok(Self(identifier))
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A digest of stable executable content on Linux.
///
/// The length varies with the hash that the deployment enables for fs-verity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentDigest(Vec<u8>);

impl ContentDigest {
    /// Creates a content digest from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest is empty.
    pub fn new(digest: impl Into<Vec<u8>>) -> Result<Self, IdentityError> {
        let digest = digest.into();
        if digest.is_empty() {
            return Err(IdentityError::Empty);
        }
        Ok(Self(digest))
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A host supplied an identity value that Fidelity cannot use.
///
/// The enumeration is `#[non_exhaustive]`, because new identity forms arrive
/// with new platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// The value holds no content.
    Empty,

    /// A hexadecimal digest has the wrong length.
    BadHexLength {
        /// The number of characters that Fidelity needs.
        expected: usize,
        /// The number of characters that the host supplied.
        actual: usize,
    },

    /// A digest holds a character outside the hexadecimal alphabet.
    NotHex,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the identity value is empty"),
            Self::BadHexLength { expected, actual } => write!(
                f,
                "the digest needs {expected} hexadecimal characters, and it has {actual}"
            ),
            Self::NotHex => f.write_str("the digest holds a character that is not hexadecimal"),
        }
    }
}

impl std::error::Error for IdentityError {}

const SHA256_HEX_LEN: usize = 64;

fn parse_sha256_hex(hex: &str) -> Result<[u8; 32], IdentityError> {
    if hex.len() != SHA256_HEX_LEN {
        return Err(IdentityError::BadHexLength {
            expected: SHA256_HEX_LEN,
            actual: hex.len(),
        });
    }

    let source = hex.as_bytes();
    let mut digest = [0_u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let high = hex_digit(source[index * 2])?;
        let low = hex_digit(source[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(digest)
}

const fn hex_digit(byte: u8) -> Result<u8, IdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(IdentityError::NotHex),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticodeThumbprint, CertificateSha256, Choice, CodeRequirement, ContentDigest,
        ExpectedIdentity, IdentityError, Platform, TeamIdentifier,
    };

    const DIGEST_HEX: &str = "9f2b1c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    #[test]
    fn a_new_identity_states_no_choice() {
        let identity = ExpectedIdentity::new();
        assert!(!identity.states_choice_for(Platform::Windows));
    }

    #[test]
    fn a_stated_value_counts_as_a_choice() {
        let identity =
            ExpectedIdentity::new().android(Choice::Value(CertificateSha256::from_bytes([0; 32])));
        assert!(identity.states_choice_for(Platform::Android));
    }

    #[test]
    fn an_accepted_gap_counts_as_a_choice() {
        let identity = ExpectedIdentity::new().linux(Choice::AcceptUnsupported);
        assert!(identity.states_choice_for(Platform::Linux));
    }

    #[test]
    fn one_platform_choice_does_not_cover_another() {
        let identity = ExpectedIdentity::new().linux(Choice::AcceptUnsupported);
        assert!(!identity.states_choice_for(Platform::MacOs));
    }

    #[test]
    fn a_thumbprint_parses_from_hex() -> Result<(), IdentityError> {
        let thumbprint = AuthenticodeThumbprint::from_hex(DIGEST_HEX)?;
        assert_eq!(thumbprint.as_bytes()[0], 0x9f);
        Ok(())
    }

    #[test]
    fn hex_parsing_accepts_upper_case() -> Result<(), IdentityError> {
        let upper = AuthenticodeThumbprint::from_hex(&DIGEST_HEX.to_uppercase())?;
        assert_eq!(upper, AuthenticodeThumbprint::from_hex(DIGEST_HEX)?);
        Ok(())
    }

    #[test]
    fn a_short_digest_reports_its_length() {
        let error = CertificateSha256::from_hex("9f2b");
        assert_eq!(
            error,
            Err(IdentityError::BadHexLength {
                expected: 64,
                actual: 4
            })
        );
    }

    #[test]
    fn a_non_hexadecimal_digest_fails() {
        let mut bad = String::from("z");
        bad.push_str(&DIGEST_HEX[1..]);
        assert_eq!(
            CertificateSha256::from_hex(&bad),
            Err(IdentityError::NotHex)
        );
    }

    #[test]
    fn an_empty_team_identifier_fails() {
        assert_eq!(TeamIdentifier::new("   "), Err(IdentityError::Empty));
    }

    #[test]
    fn an_empty_code_requirement_fails() {
        assert_eq!(CodeRequirement::new(""), Err(IdentityError::Empty));
    }

    #[test]
    fn an_empty_content_digest_fails() {
        assert_eq!(ContentDigest::new(Vec::new()), Err(IdentityError::Empty));
    }

    #[test]
    fn a_content_digest_keeps_its_bytes() -> Result<(), IdentityError> {
        let digest = ContentDigest::new(vec![1, 2, 3])?;
        assert_eq!(digest.as_bytes(), &[1, 2, 3]);
        Ok(())
    }
}
