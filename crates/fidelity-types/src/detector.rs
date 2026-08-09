use core::hash::{Hash, Hasher};

use crate::Category;

/// An opaque identity for one built-in detector.
///
/// The detector inventory is not a public enumeration, so a new detector is
/// not a breaking change. A host routes on the [`Category`] and logs the
/// [`name`](Detector::name).
///
/// Two detectors compare equal when they share an identity. The name and the
/// category take no part in the comparison, so a rename never splits a state
/// slot.
#[derive(Debug, Clone, Copy)]
pub struct Detector {
    id: u16,
    name: &'static str,
    category: Category,
}

impl Detector {
    /// Creates a detector identity.
    ///
    /// Only Fidelity's own crates call this. It is not part of the supported
    /// surface, and it carries no compatibility promise.
    #[doc(hidden)]
    #[must_use]
    pub const fn new(id: u16, name: &'static str, category: Category) -> Self {
        Self { id, name, category }
    }

    /// The stable name of this detector.
    ///
    /// The name is a log and report value. A host must not parse it, and must
    /// not branch on it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The category that this detector reports into.
    #[must_use]
    pub const fn category(self) -> Category {
        self.category
    }
}

impl PartialEq for Detector {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Detector {}

impl PartialOrd for Detector {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Detector {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl Hash for Detector {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::Detector;
    use crate::Category;

    const A: Detector = Detector::new(1, "test.a", Category::Integrity);
    const B: Detector = Detector::new(2, "test.b", Category::Debugging);

    #[test]
    fn a_detector_reports_its_name() {
        assert_eq!(A.name(), "test.a");
    }

    #[test]
    fn a_detector_reports_its_category() {
        assert_eq!(A.category(), Category::Integrity);
    }

    #[test]
    fn distinct_identities_differ() {
        assert_ne!(A, B);
    }

    #[test]
    fn a_rename_keeps_the_identity() {
        let renamed = Detector::new(1, "test.renamed", Category::UiAbuse);
        assert_eq!(A, renamed);
    }
}
