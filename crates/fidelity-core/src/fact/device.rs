//! The facts that the device capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about its own build.
///
/// The capability answers one question: did the vendor of this system release
/// the build that runs now? A vendor release build closes the settings that a
/// development build keeps open, and root needs one of those settings or a
/// replaced system image. The question therefore covers the common route to
/// root without naming a tool, a package, or a path.
///
/// It does not answer whether a process holds privilege now. A system that
/// reports a release build can still be rooted, and
/// [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
/// states that limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemBuild {
    /// The system reports a build that its vendor released.
    Released,

    /// The system reports a build that no vendor released, or one that keeps a
    /// development setting open.
    Development {
        /// Which interface disagreed, in text that holds no application data.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::SystemBuild;

    #[test]
    fn a_development_build_keeps_its_detail() {
        let build = SystemBuild::Development {
            detail: BoundedText::new("the system reports ro.debuggable=1"),
        };
        assert_eq!(
            build,
            SystemBuild::Development {
                detail: BoundedText::new("the system reports ro.debuggable=1"),
            }
        );
    }

    #[test]
    fn a_released_build_differs_from_a_development_one() {
        assert_ne!(
            SystemBuild::Released,
            SystemBuild::Development {
                detail: BoundedText::new("the system reports ro.debuggable=1"),
            }
        );
    }
}
