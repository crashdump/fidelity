use core::fmt;

use fidelity_types::{CategorySet, Platform};

/// A fundamental failure that prevents the start.
///
/// Every case is distinct and typed. Fidelity does not flatten a start
/// failure into an unstructured string.
///
/// A failed start releases the process-wide slot, so one bad configuration
/// never blocks a corrected retry.
///
/// The enumeration is `#[non_exhaustive]`, because every platform backend
/// adds initialization failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartError {
    /// A runtime already holds the process-wide slot.
    ///
    /// Treat this as fatal. Protection runs for the life of the process, so a
    /// second start never succeeds, and the policy in force is not the policy
    /// that this call asked for.
    AlreadyRunning,

    /// A category selects `Callback`, and the builder received no callback.
    MissingCallback,

    /// The host supplied expected identity, but stated no choice for this
    /// target.
    ///
    /// A host that calls the identity setter makes the check required. Every
    /// platform it ships to needs either a value or an accepted gap. Silence
    /// states nothing, so Fidelity refuses to guess.
    MissingExpectedIdentity {
        /// The platform that this build targets.
        platform: Platform,
    },

    /// The build binds guarded constants to a code identity, and the running
    /// image reports none.
    ///
    /// The key of a guarded constant comes from the per-build salt and the
    /// code identity that the operating system reports. A build that names an
    /// identity, on an image that reports none, derives a different key at
    /// every read, so each guarded constant gives a wrong value. A guarded
    /// read has no error path by design, so nothing later reports the fault.
    /// The start fails instead, because a host that reads a wrong value finds
    /// out where the value is used and not where the fault is.
    ///
    /// Two answers fix it. Sign the image with the identity that the build
    /// names, or set `FIDELITY_CODE_IDENTITY=none` to state that this build
    /// binds to no identity.
    IdentityBindingUnavailable {
        /// The platform that this build targets.
        platform: Platform,

        /// Why the running image reports no code identity.
        reason: &'static str,
    },

    /// This build targets a platform outside the supported set.
    UnsupportedTarget,

    /// Fidelity could not construct a platform backend.
    PlatformUnavailable {
        /// Why the backend is not available on this target.
        reason: &'static str,
    },

    /// The operating system refused to create the worker thread.
    ///
    /// Fidelity owns its worker, so a runtime without one detects nothing
    /// after the initial scan. The start fails rather than report coverage
    /// that no worker produces.
    WorkerUnavailable {
        /// What the operating system reported.
        reason: std::io::ErrorKind,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => f.write_str("a fidelity runtime already runs in this process"),
            Self::MissingCallback => {
                f.write_str("a category selects Callback, and no callback was supplied")
            }
            Self::MissingExpectedIdentity { platform } => write!(
                f,
                "expected identity states no choice for the target platform {platform:?}"
            ),
            Self::IdentityBindingUnavailable { platform, reason } => write!(
                f,
                "this build binds guarded constants to a code identity, and the target platform \
                 {platform:?} supplies none. {reason} Sign the image with the identity that the \
                 build names, or set FIDELITY_CODE_IDENTITY=none"
            ),
            Self::UnsupportedTarget => {
                f.write_str("this build targets a platform that fidelity does not support")
            }
            Self::PlatformUnavailable { reason } => {
                write!(f, "no platform backend is available: {reason}")
            }
            Self::WorkerUnavailable { reason } => {
                write!(
                    f,
                    "the operating system refused the worker thread: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for StartError {}

/// Why a protected operation is not allowed.
///
/// The enumeration is `#[non_exhaustive]`, because a later release may deny
/// for a reason that v1 does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DenialReason {
    /// At least one category holds a permanent denial latch.
    Latched,

    /// The detectors have not all run yet.
    ///
    /// The host called `Builder::deny_until_first_full_scan`, and the worker
    /// has not completed its first full cycle. The initial scan covers the
    /// cheap detectors only, so root, jailbreak, emulator, and UI evidence
    /// does not exist yet. Nothing latched. The coverage is absent.
    IncompleteCoverage,
}

/// A protected operation is not allowed.
///
/// The denial is process-wide. A latch is permanent, and a denial for absent
/// coverage clears when the first full scan completes.
///
/// Read [`reason`](Denied::reason) to tell the two apart, and read the
/// snapshot for the finding behind a latch.
///
/// This check is advisory. An attacker who patches the process can invert it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    categories: CategorySet,
    reason: DenialReason,
}

impl Denied {
    pub(crate) const fn latched(categories: CategorySet) -> Self {
        Self {
            categories,
            reason: DenialReason::Latched,
        }
    }

    pub(crate) const fn incomplete_coverage() -> Self {
        Self {
            categories: CategorySet::new(),
            reason: DenialReason::IncompleteCoverage,
        }
    }

    /// The categories that latched the denial.
    ///
    /// The set is empty when the reason is
    /// [`IncompleteCoverage`](DenialReason::IncompleteCoverage), because no
    /// category latched.
    #[must_use]
    pub const fn categories(&self) -> CategorySet {
        self.categories
    }

    /// Why the operation is not allowed.
    #[must_use]
    pub const fn reason(&self) -> DenialReason {
        self.reason
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            DenialReason::Latched => f.write_str("a fidelity category latched a denial"),
            DenialReason::IncompleteCoverage => {
                f.write_str("the fidelity detectors have not all run yet")
            }
        }
    }
}

impl std::error::Error for Denied {}

#[cfg(test)]
mod tests {
    use super::{DenialReason, Denied, StartError};
    use fidelity_types::{Category, CategorySet, Platform};

    #[test]
    fn a_denial_reports_its_categories() {
        let mut categories = CategorySet::new();
        categories.insert(Category::Integrity);
        assert!(
            Denied::latched(categories)
                .categories()
                .contains(Category::Integrity)
        );
    }

    #[test]
    fn a_latched_denial_states_that_reason() {
        let denial = Denied::latched(CategorySet::new());
        assert_eq!(denial.reason(), DenialReason::Latched);
    }

    #[test]
    fn a_denial_for_absent_coverage_latches_no_category() {
        let denial = Denied::incomplete_coverage();
        assert_eq!(denial.reason(), DenialReason::IncompleteCoverage);
        assert!(denial.categories().is_empty());
    }

    #[test]
    fn the_two_denial_reasons_read_differently() {
        let latched = Denied::latched(CategorySet::new()).to_string();
        let coverage = Denied::incomplete_coverage().to_string();
        assert_ne!(latched, coverage);
    }

    #[test]
    fn a_start_error_names_the_platform_that_lacks_a_choice() {
        let error = StartError::MissingExpectedIdentity {
            platform: Platform::Linux,
        };
        assert!(error.to_string().contains("Linux"));
    }

    #[test]
    fn a_start_error_describes_a_singleton_conflict() {
        assert!(StartError::AlreadyRunning.to_string().contains("already"));
    }
}
