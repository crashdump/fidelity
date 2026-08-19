//! The facts that the dispatch capability reports.
//!
//! A loader resolves an imported call through a table of pointers, and each
//! entry of that table is a dispatch target. A hook that rewrites one entry
//! redirects the call and maps no new executable region, so the
//! [runtime baseline](../baseline/index.html) reports clean and no
//! executable-memory rule reaches the table, which holds data.
//!
//! This fact records the dispatch targets of the main image, the one image
//! that the host controls and that an attacker rewrites to intercept the
//! host's own calls. It records the main image alone, because a shared library
//! can hold thousands of targets and the memory of the snapshot must stay
//! bounded. Measured on Linux and ARM64: a Rust main image holds about 80.

/// One dispatch target: where the entry sits, and where it points now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    slot: u64,
    value: u64,
}

impl Target {
    /// Creates a target from the address of the table entry and its value.
    #[must_use]
    pub const fn new(slot: u64, value: u64) -> Self {
        Self { slot, value }
    }

    /// The address of the table entry.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.slot
    }

    /// The address that the entry points at now.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// How many dispatch targets one snapshot keeps.
///
/// The snapshot records the main image alone, which holds far fewer targets
/// than a shared library. Measured on Linux and ARM64: a Rust main image holds
/// about 80. The limit keeps the memory that the snapshot costs fixed, and a
/// main image that passes it reports that fact rather than a partial answer
/// that reads as complete.
pub const MAX_TARGETS: usize = 4096;

/// The dispatch targets of the main image.
///
/// The capability answers what the targets are. It does not answer whether
/// they changed: a detector compares a later snapshot against the one that
/// `start()` captured.
///
/// A snapshot states whether the loader bound the whole table before the
/// process ran. A table that the loader binds on the first call rewrites its
/// own entries later, which reads exactly as a hook reads, so a snapshot of a
/// table that is not fully bound cannot support the comparison. Measured on
/// Linux and ARM64: a Rust main image is fully bound, because the toolchain
/// links it with full read-only relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTargets {
    targets: Vec<Target>,
    bound: bool,
    truncated: bool,
}

impl DispatchTargets {
    /// Creates a snapshot, and keeps [`MAX_TARGETS`] targets at most.
    ///
    /// The targets arrive in slot order, and the snapshot keeps that order, so
    /// a comparison never depends on how a platform enumerates them.
    #[must_use]
    pub fn new(mut targets: Vec<Target>, bound: bool) -> Self {
        targets.sort_unstable();
        let truncated = targets.len() > MAX_TARGETS;
        targets.truncate(MAX_TARGETS);
        Self {
            targets,
            bound,
            truncated,
        }
    }

    /// The targets, in slot order.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// Whether the loader bound the whole table before the process ran.
    ///
    /// A table that is not fully bound rewrites its own entries on the first
    /// call, so a change there is ordinary and the comparison cannot run.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.bound
    }

    /// Whether the main image holds more targets than the snapshot keeps.
    ///
    /// A truncated snapshot cannot state that a target changed, because the
    /// target it would compare against may be one of the targets it dropped.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The targets of `self` whose slot `start` held with another value.
    ///
    /// A target counts as redirected when `start` held the same slot and the
    /// slot points somewhere else now. A slot that `start` did not hold is not
    /// compared, because the snapshot cannot state what it pointed at before.
    #[must_use]
    pub fn redirected_since(&self, start: &Self) -> Vec<Target> {
        self.targets
            .iter()
            .filter(|target| {
                start
                    .targets
                    .iter()
                    .any(|before| before.slot == target.slot && before.value != target.value)
            })
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{DispatchTargets, MAX_TARGETS, Target};

    fn bound(pairs: &[(u64, u64)]) -> DispatchTargets {
        DispatchTargets::new(
            pairs
                .iter()
                .map(|&(slot, value)| Target::new(slot, value))
                .collect(),
            true,
        )
    }

    #[test]
    fn an_unchanged_table_reports_no_redirect() {
        let start = bound(&[(0x1000, 0xa000), (0x1008, 0xb000)]);
        assert!(start.redirected_since(&start).is_empty());
    }

    #[test]
    fn a_slot_that_points_elsewhere_reads_as_redirected() {
        let start = bound(&[(0x1000, 0xa000), (0x1008, 0xb000)]);
        let now = bound(&[(0x1000, 0xa000), (0x1008, 0xc000)]);
        assert_eq!(
            now.redirected_since(&start),
            vec![Target::new(0x1008, 0xc000)]
        );
    }

    #[test]
    fn a_slot_that_start_did_not_hold_is_not_compared() {
        // The snapshot cannot state what a new slot pointed at before, so it
        // never reports one. A main image table does not grow in practice.
        let start = bound(&[(0x1000, 0xa000)]);
        let now = bound(&[(0x1000, 0xa000), (0x1008, 0xc000)]);
        assert!(now.redirected_since(&start).is_empty());
    }

    #[test]
    fn a_snapshot_keeps_its_targets_in_slot_order() {
        let snapshot = bound(&[(0x1008, 0xb000), (0x1000, 0xa000)]);
        assert_eq!(
            snapshot.targets().first(),
            Some(&Target::new(0x1000, 0xa000))
        );
    }

    #[test]
    fn a_snapshot_that_passes_the_limit_reports_it() {
        let pairs: Vec<(u64, u64)> = (0..=MAX_TARGETS as u64)
            .map(|index| (index * 8, index * 0x1000))
            .collect();
        assert!(bound(&pairs).is_truncated());
    }

    #[test]
    fn a_snapshot_that_passes_the_limit_keeps_the_limit() {
        let pairs: Vec<(u64, u64)> = (0..=MAX_TARGETS as u64)
            .map(|index| (index * 8, index * 0x1000))
            .collect();
        assert_eq!(bound(&pairs).targets().len(), MAX_TARGETS);
    }

    #[test]
    fn a_snapshot_inside_the_limit_reports_no_truncation() {
        assert!(!bound(&[(0x1000, 0xa000)]).is_truncated());
    }

    #[test]
    fn a_snapshot_states_whether_the_table_is_bound() {
        assert!(bound(&[(0x1000, 0xa000)]).is_bound());
        let lazy = DispatchTargets::new(vec![Target::new(0x1000, 0xa000)], false);
        assert!(!lazy.is_bound());
    }
}
