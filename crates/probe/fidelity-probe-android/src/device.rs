//! The system build on Android.
//!
//! Android states what it is in its own property store. Two properties answer
//! the question that
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! asks: does the vendor of this system release the build that runs now? That
//! document holds the strength and the two coverage limits.

use core::ffi::CStr;

use fidelity_core::{Device, Observation, SystemBuild};
use fidelity_types::BoundedText;

use super::AndroidEnvironment;
use crate::sys::property;

/// The property that states whether the system allows a debugger on any
/// application.
const DEBUGGABLE: &CStr = c"ro.debuggable";

/// The property that names the keys that signed the system build.
const TAGS: &CStr = c"ro.build.tags";

/// What `ro.debuggable` holds on a build that keeps that setting open.
const DEBUGGABLE_OPEN: &str = "1";

/// The markers that name a key which no vendor releases.
///
/// `test-keys` is the public AOSP key, which everybody holds. `dev-keys` is a
/// local key. Measured on 2026-08-10: a Play Store system image reports
/// `release-keys`, and a Google APIs image reports `dev-keys`.
///
/// The rule names the two markers rather than accepting `release-keys` alone.
/// No survey covers what every vendor writes here, so an unknown value is not
/// evidence, and a system that writes one reports no finding.
const DEVELOPMENT_KEYS: [&str; 2] = ["test-keys", "dev-keys"];

/// What an open debug setting reports.
const DEBUGGER_ALLOWED: &str =
    "the system reports ro.debuggable=1, so it allows a debugger on any application";

/// What a development key reports.
const NOT_A_RELEASE_KEY: &str = "the system reports ro.build.tags without a vendor release key";

/// What an empty property store reports.
const NO_PROPERTY: &str = "the property store did not state both ro.debuggable and ro.build.tags";

impl Device for AndroidEnvironment {
    fn system_build(&self) -> Observation<SystemBuild> {
        match judge(
            property::read(DEBUGGABLE).as_deref(),
            property::read(TAGS).as_deref(),
        ) {
            Ok(build) => Observation::Fact(build),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Decides what the two properties state about this build.
///
/// The decision is a plain function, so a test proves every answer on one
/// system. Two system images are needed to reach both live answers, and
/// `evidence/README.md` records that pair.
///
/// # Errors
///
/// Returns the reason when no single property proves a development build and
/// the store did not state both. Every Android system holds both, so an absent
/// property is a failed read and never a released build.
fn judge(debuggable: Option<&str>, tags: Option<&str>) -> Result<SystemBuild, &'static str> {
    // One property alone proves a development build, so these two answers
    // stand whatever the other property says, and a failed read of the other
    // one changes nothing.
    if debuggable == Some(DEBUGGABLE_OPEN) {
        return Ok(development(DEBUGGER_ALLOWED));
    }
    if tags.is_some_and(names_a_development_key) {
        return Ok(development(NOT_A_RELEASE_KEY));
    }
    // Only `Released` is left, and that answer needs both inputs. Android
    // supplies both, so one absent property is a failed read. Reporting it as
    // released would turn a broken probe into a clean control.
    if debuggable.is_none() || tags.is_none() {
        return Err(NO_PROPERTY);
    }
    Ok(SystemBuild::Released)
}

/// Reports whether a tags value names a key that no vendor releases.
fn names_a_development_key(tags: &str) -> bool {
    DEVELOPMENT_KEYS.iter().any(|marker| tags.contains(marker))
}

/// Builds the fact that a development build reports.
fn development(detail: &'static str) -> SystemBuild {
    SystemBuild::Development {
        detail: BoundedText::new(detail),
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Device, Observation, SystemBuild};

    use super::{AndroidEnvironment, judge};

    #[test]
    fn the_probe_reads_the_build_of_this_system() {
        // The live control. Which answer it gives depends on the system image,
        // and both images are recorded evidence. A failure is what must never
        // happen, because every Android system holds these properties.
        let observation = AndroidEnvironment::new().system_build();
        assert!(
            matches!(observation, Observation::Fact(_)),
            "{observation:?}"
        );
    }

    #[test]
    fn a_release_build_reports_no_finding() {
        let Ok(build) = judge(Some("0"), Some("release-keys")) else {
            panic!("a stated property is never a failed read")
        };
        assert_eq!(build, SystemBuild::Released);
    }

    #[test]
    fn an_open_debug_setting_reports_a_development_build() {
        let Ok(build) = judge(Some("1"), Some("release-keys")) else {
            panic!("a stated property is never a failed read")
        };
        assert!(matches!(build, SystemBuild::Development { .. }));
    }

    #[test]
    fn a_development_key_reports_a_development_build() {
        let Ok(build) = judge(Some("0"), Some("dev-keys")) else {
            panic!("a stated property is never a failed read")
        };
        assert!(matches!(build, SystemBuild::Development { .. }));
    }

    #[test]
    fn the_public_test_key_reports_a_development_build() {
        let Ok(build) = judge(Some("0"), Some("test-keys")) else {
            panic!("a stated property is never a failed read")
        };
        assert!(matches!(build, SystemBuild::Development { .. }));
    }

    #[test]
    fn a_tags_value_that_no_survey_covers_reports_no_finding() {
        // The rule names the two markers it knows. An unknown value is not
        // evidence, because a vendor may write anything here and a clean
        // control that reports is worse than one that stays quiet.
        let Ok(build) = judge(Some("0"), Some("vendor-keys")) else {
            panic!("a stated property is never a failed read")
        };
        assert_eq!(build, SystemBuild::Released);
    }

    #[test]
    fn an_empty_property_store_reports_a_health_finding() {
        // Never a released build. A store that states nothing is a failed
        // read, and Fidelity never reports a failed read as a clean result.
        assert!(judge(None, None).is_err());
    }

    #[test]
    fn one_stated_property_is_enough_to_decide() {
        let Ok(build) = judge(None, Some("dev-keys")) else {
            panic!("one stated property is never a failed read")
        };
        assert!(matches!(build, SystemBuild::Development { .. }));
    }

    #[test]
    fn one_absent_property_never_reports_a_release() {
        // The other property looks benign, and that is exactly the case that
        // must not read as clean. Android states both, so an absent one is a
        // failed read, and only a stated pair proves a released build.
        assert!(judge(None, Some("release-keys")).is_err());
        assert!(judge(Some("0"), None).is_err());
    }
}
