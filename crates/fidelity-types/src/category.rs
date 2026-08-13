/// A broad security question that Fidelity answers.
///
/// The category is the configuration boundary. Each category carries one
/// action and one threshold, and there is no per-detector public policy.
///
/// The enumeration is `#[non_exhaustive]`, because the project may add a
/// category after v1. A host match therefore needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Category {
    /// Something modified executable code, a trusted image, or process state.
    Integrity,

    /// A debugger or a tracer interacts with the process, or did so before.
    Debugging,

    /// A runtime hook, an injection, or dynamic instrumentation is present.
    Instrumentation,

    /// Root, jailbreak, or an equivalent compromise weakens the OS security
    /// model.
    DeviceCompromise,

    /// The application runs in an emulator, a simulator, a virtual machine, a
    /// container, or an analysis environment.
    Virtualization,

    /// Another application reads or drives this application's user interface.
    UiAbuse,
}

impl Category {
    /// Every v1 category.
    pub const ALL: [Self; 6] = [
        Self::Integrity,
        Self::Debugging,
        Self::Instrumentation,
        Self::DeviceCompromise,
        Self::Virtualization,
        Self::UiAbuse,
    ];

    /// The number of v1 categories.
    pub const COUNT: usize = Self::ALL.len();

    /// The stable position of this category.
    ///
    /// Fidelity's own crates index fixed-size tables with this. It is not
    /// part of the supported surface, and it carries no compatibility
    /// promise.
    ///
    /// The match is exhaustive inside this crate, so a new category fails to
    /// compile until it gets a position here.
    #[doc(hidden)]
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Integrity => 0,
            Self::Debugging => 1,
            Self::Instrumentation => 2,
            Self::DeviceCompromise => 3,
            Self::Virtualization => 4,
            Self::UiAbuse => 5,
        }
    }
}

/// A set of categories.
///
/// The set is a fixed-size value. It allocates nothing, so a check of the
/// denial state costs one read.
///
/// # Examples
///
/// ```
/// use fidelity_types::{Category, CategorySet};
///
/// let mut set = CategorySet::new();
/// assert!(set.is_empty());
///
/// set.insert(Category::Integrity);
/// assert!(set.contains(Category::Integrity));
/// assert!(!set.contains(Category::Debugging));
/// assert_eq!(set.len(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CategorySet(u32);

impl CategorySet {
    /// Creates an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Adds a category, and reports whether the set changed.
    pub fn insert(&mut self, category: Category) -> bool {
        let mask = 1_u32 << category.index();
        let changed = self.0 & mask == 0;
        self.0 |= mask;
        changed
    }

    /// Reports whether the set holds this category.
    #[must_use]
    pub const fn contains(self, category: Category) -> bool {
        self.0 & (1_u32 << category.index()) != 0
    }

    /// Reports whether the set holds no category.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Counts the categories in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Iterates the categories in the set, in declaration order.
    #[must_use]
    pub fn iter(self) -> CategorySetIter {
        CategorySetIter { set: self, next: 0 }
    }

    /// The raw bits of the set.
    ///
    /// Fidelity's own crates hold the denial latch in one atomic word, so
    /// that a check of the latch reads it without a lock. This is not part of
    /// the supported surface.
    #[doc(hidden)]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Rebuilds a set from raw bits.
    ///
    /// Fidelity's own crates call this. It is not part of the supported
    /// surface.
    #[doc(hidden)]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

impl IntoIterator for CategorySet {
    type Item = Category;
    type IntoIter = CategorySetIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterates the categories that a [`CategorySet`] holds.
#[derive(Debug, Clone)]
pub struct CategorySetIter {
    set: CategorySet,
    next: usize,
}

impl Iterator for CategorySetIter {
    type Item = Category;

    fn next(&mut self) -> Option<Category> {
        while self.next < Category::ALL.len() {
            let category = Category::ALL[self.next];
            self.next += 1;
            if self.set.contains(category) {
                return Some(category);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Category, CategorySet};

    #[test]
    fn a_new_set_is_empty() {
        assert!(CategorySet::new().is_empty());
    }

    #[test]
    fn insert_reports_the_first_change_only() {
        let mut set = CategorySet::new();
        assert!(set.insert(Category::Debugging));
        assert!(!set.insert(Category::Debugging));
    }

    #[test]
    fn a_set_holds_only_what_it_receives() {
        let mut set = CategorySet::new();
        set.insert(Category::UiAbuse);
        assert!(!set.contains(Category::Integrity));
    }

    #[test]
    fn a_set_holds_every_category_at_once() {
        let mut set = CategorySet::new();
        for category in Category::ALL {
            set.insert(category);
        }
        assert_eq!(set.len(), Category::ALL.len());
    }

    #[test]
    fn iteration_follows_declaration_order() {
        let mut set = CategorySet::new();
        set.insert(Category::UiAbuse);
        set.insert(Category::Integrity);
        let seen: Vec<Category> = set.iter().collect();
        assert_eq!(seen, vec![Category::Integrity, Category::UiAbuse]);
    }

    #[test]
    fn every_category_takes_a_distinct_position() {
        let mut set = CategorySet::new();
        for category in Category::ALL {
            assert!(set.insert(category), "{category:?} shares a position");
        }
    }
}
