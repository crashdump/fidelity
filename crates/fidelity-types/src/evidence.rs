/// The size limit for retained evidence, in bytes.
///
/// Long-running memory use must not depend on finding frequency or on an
/// attacker-chosen identifier, so every text field carries this bound.
pub const MAX_EVIDENCE_BYTES: usize = 4096;

/// Text that Fidelity truncates to [`MAX_EVIDENCE_BYTES`].
///
/// The type keeps the truncation visible, so a reader never mistakes a cut
/// value for a complete one. Truncation stops on a character boundary, so the
/// result is always valid text.
///
/// # Examples
///
/// ```
/// use fidelity_types::BoundedText;
///
/// let short = BoundedText::new("mach_task_self returned KERN_FAILURE");
/// assert!(!short.is_truncated());
/// assert_eq!(short.text(), "mach_task_self returned KERN_FAILURE");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedText {
    text: String,
    truncated: bool,
}

impl BoundedText {
    /// Creates bounded text, and truncates it when it exceeds the limit.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        let mut text = text.into();
        if text.len() <= MAX_EVIDENCE_BYTES {
            return Self {
                text,
                truncated: false,
            };
        }

        // `truncate` panics on an interior byte, so step back to a boundary.
        let mut end = MAX_EVIDENCE_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        Self {
            text,
            truncated: true,
        }
    }

    /// The retained text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Reports whether Fidelity cut the original text.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Typed detail that explains one finding.
///
/// Evidence states the mechanism without exposure of an application secret.
///
/// The enumeration is `#[non_exhaustive]`, because it grows as detectors
/// arrive. Every variant beyond detector health waits for a real backend and
/// its clean and hostile evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Evidence {
    /// A detector could not complete its check.
    ///
    /// Fidelity never converts a detector error into a clean result, so an
    /// unexpected failure carries this evidence at `Low` strength.
    DetectorHealth {
        /// What failed, in text that holds no application data.
        detail: BoundedText,
    },

    /// The operating system did not validate the running image.
    ///
    /// This is the platform-trust tier. It needs no host input, and it states
    /// that a party the machine trusts did not sign the running image.
    ImageUntrusted {
        /// What the operating system reported.
        detail: BoundedText,
    },

    /// The running image does not satisfy the identity that the host pinned.
    ///
    /// This is the expected-identity tier, and it is the only local evidence
    /// that identifies a repackaged application.
    UnexpectedIdentity {
        /// What differs, in text that holds no application data.
        detail: BoundedText,
    },

    /// A debugger or a tracer holds the process.
    ///
    /// The evidence names the interface that reported the state, because a
    /// platform may hold more than one, and they can disagree.
    TracerPresent {
        /// What the operating system reported.
        detail: BoundedText,
    },

    /// The process executes code that no file accounts for.
    ///
    /// A loader maps code from a file. Executable memory with no file behind
    /// it arrived another way, and an injected agent is the common reason.
    UnaccountedCode {
        /// How many regions, and where they sit.
        detail: BoundedText,
    },

    /// The process maps executable code that it did not map at start.
    ///
    /// This is the runtime baseline. It answers what an absolute rule cannot
    /// answer on every platform, because a change since start needs no
    /// judgement about what normal looks like.
    CodeAddedAfterStart {
        /// How much code arrived, and in how many regions.
        detail: BoundedText,
    },

    /// The system states that no vendor released the build that runs now.
    ///
    /// The evidence names the setting that the system left open, because a
    /// build states more than one and a host acts on which one it was.
    DevelopmentBuild {
        /// What the system stated, in text that names no tool and no path.
        detail: BoundedText,
    },
}

impl Evidence {
    /// Reports whether this evidence describes a Fidelity failure.
    ///
    /// Detector health describes Fidelity, not the host's environment. Policy
    /// treats it differently for that reason: `Action::Crash` never fires on
    /// it, because a transient failure of Fidelity's own check must not
    /// terminate somebody else's process.
    #[must_use]
    pub const fn is_detector_health(&self) -> bool {
        matches!(self, Self::DetectorHealth { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedText, MAX_EVIDENCE_BYTES};

    #[test]
    fn short_text_survives_whole() {
        let text = BoundedText::new("ptrace returned EPERM");
        assert_eq!(text.text(), "ptrace returned EPERM");
    }

    #[test]
    fn short_text_reports_no_truncation() {
        assert!(!BoundedText::new("small").is_truncated());
    }

    #[test]
    fn long_text_reports_truncation() {
        let text = BoundedText::new("a".repeat(MAX_EVIDENCE_BYTES + 1));
        assert!(text.is_truncated());
    }

    #[test]
    fn long_text_stays_within_the_limit() {
        let text = BoundedText::new("a".repeat(MAX_EVIDENCE_BYTES * 4));
        assert!(text.text().len() <= MAX_EVIDENCE_BYTES);
    }

    #[test]
    fn truncation_stops_on_a_character_boundary() {
        // Every character takes 4 bytes, so the limit lands mid character.
        let text = BoundedText::new("😀".repeat(MAX_EVIDENCE_BYTES));
        assert!(text.text().len() <= MAX_EVIDENCE_BYTES);
        assert_eq!(text.text().len() % 4, 0);
    }

    #[test]
    fn text_at_exactly_the_limit_survives_whole() {
        let text = BoundedText::new("a".repeat(MAX_EVIDENCE_BYTES));
        assert!(!text.is_truncated());
    }
}
