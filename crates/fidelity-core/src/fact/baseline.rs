//! The facts that the runtime baseline capability reports.

/// One executable region of the process.
///
/// The region carries its protection as well as its range, because the
/// [runtime baseline](../../../../docs/plan/04-detectors-and-platforms.md)
/// records both. A range alone cannot state that a region which the process
/// mapped as read and execute at start is now writable as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Region {
    start: u64,
    end: u64,
    writable: bool,
}

impl Region {
    /// Creates a region from its range and whether it is writable.
    ///
    /// Every region here is executable, because a snapshot holds no other
    /// kind, so `writable` states whether the region is writable as well.
    #[must_use]
    pub const fn new(start: u64, end: u64, writable: bool) -> Self {
        Self {
            start,
            end,
            writable,
        }
    }

    /// Reports whether the region is writable as well as executable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// The first address of the region.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// The address after the region.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// The size of the region, in bytes.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Reports whether this region holds an address.
    #[must_use]
    pub const fn holds(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

/// How many regions one snapshot keeps.
///
/// A process maps a few hundred executable regions at most. Measured on
/// Android 37: a system application maps 410. The limit keeps the memory that
/// the baseline costs fixed, and a process that passes it reports that fact
/// rather than a partial answer that reads as complete.
pub const MAX_REGIONS: usize = 1024;

/// The executable regions that the process maps now.
///
/// The capability answers what the regions are. It does not answer whether
/// they changed: a detector compares a later snapshot against the one that
/// `start()` captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegions {
    regions: Vec<Region>,
    truncated: bool,
}

impl CodeRegions {
    /// Creates a snapshot, and keeps [`MAX_REGIONS`] regions at most.
    ///
    /// The regions arrive in address order, and the snapshot keeps that order,
    /// so a comparison never depends on how a platform enumerates them.
    #[must_use]
    pub fn new(mut regions: Vec<Region>) -> Self {
        regions.sort_unstable();
        let truncated = regions.len() > MAX_REGIONS;
        regions.truncate(MAX_REGIONS);
        Self { regions, truncated }
    }

    /// The regions, in address order.
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Reports whether the process mapped more regions than the snapshot keeps.
    ///
    /// A truncated snapshot cannot state that a region is new, because the
    /// region it would compare against may be one of the regions it dropped.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The regions of `self` that no region of `earlier` holds.
    ///
    /// A region counts as new when its first address sits inside no earlier
    /// region. A region that grew keeps its first address, so it is not new,
    /// and a compiler that writes code inside a pool it already reserved adds
    /// nothing here.
    #[must_use]
    pub fn added_since(&self, earlier: &Self) -> Vec<Region> {
        self.regions
            .iter()
            .filter(|region| {
                !earlier
                    .regions
                    .iter()
                    .any(|known| known.holds(region.start()))
            })
            .copied()
            .collect()
    }

    /// The regions of `self` that `earlier` held, and held as not writable.
    ///
    /// A region keeps its first address when something changes its
    /// protection, so [`added_since`](CodeRegions::added_since) reports
    /// nothing for it. This states the other half: code that the process
    /// mapped as read and execute, and that something has made writable since.
    #[must_use]
    pub fn now_writable_since(&self, earlier: &Self) -> Vec<Region> {
        self.regions
            .iter()
            .filter(|region| region.writable)
            .filter(|region| {
                earlier
                    .regions
                    .iter()
                    .any(|known| known.start == region.start && !known.writable)
            })
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{CodeRegions, MAX_REGIONS, Region};

    fn regions(pairs: &[(u64, u64)]) -> CodeRegions {
        CodeRegions::new(
            pairs
                .iter()
                .map(|&(start, end)| Region::new(start, end, false))
                .collect(),
        )
    }

    /// The same snapshot, with every region writable as well as executable.
    fn writable(pairs: &[(u64, u64)]) -> CodeRegions {
        CodeRegions::new(
            pairs
                .iter()
                .map(|&(start, end)| Region::new(start, end, true))
                .collect(),
        )
    }

    #[test]
    fn an_unchanged_process_adds_no_region() {
        let first = regions(&[(0x1000, 0x2000), (0x5000, 0x6000)]);
        assert!(first.added_since(&first).is_empty());
    }

    #[test]
    fn a_fresh_region_reads_as_added() {
        let first = regions(&[(0x1000, 0x2000)]);
        let later = regions(&[(0x1000, 0x2000), (0x9000, 0xa000)]);
        assert_eq!(
            later.added_since(&first),
            vec![Region::new(0x9000, 0xa000, false)]
        );
    }

    #[test]
    fn a_region_that_grew_never_reads_as_added() {
        // A compiler that reserves a pool and then extends it keeps the same
        // first address. Treating that as new would report every such runtime.
        let first = regions(&[(0x1000, 0x2000)]);
        let later = regions(&[(0x1000, 0x8000)]);
        assert!(later.added_since(&first).is_empty());
    }

    #[test]
    fn code_written_inside_a_reserved_pool_never_reads_as_added() {
        // Measured on macOS: a JavaScript engine carves its compiled code out
        // of a region that it reserved before the baseline.
        let first = regions(&[(0x1000, 0x9000)]);
        let later = regions(&[(0x1000, 0x9000), (0x4000, 0x5000)]);
        assert!(later.added_since(&first).is_empty());
    }

    #[test]
    fn a_region_that_went_away_adds_nothing() {
        let first = regions(&[(0x1000, 0x2000), (0x5000, 0x6000)]);
        let later = regions(&[(0x1000, 0x2000)]);
        assert!(later.added_since(&first).is_empty());
    }

    #[test]
    fn a_snapshot_keeps_its_regions_in_address_order() {
        let snapshot = regions(&[(0x5000, 0x6000), (0x1000, 0x2000)]);
        assert_eq!(
            snapshot.regions().first(),
            Some(&Region::new(0x1000, 0x2000, false))
        );
    }

    #[test]
    fn a_snapshot_that_passes_the_limit_reports_it() {
        let pairs: Vec<(u64, u64)> = (0..=MAX_REGIONS as u64)
            .map(|index| (index * 0x2000, index * 0x2000 + 0x1000))
            .collect();
        assert!(regions(&pairs).is_truncated());
    }

    #[test]
    fn a_snapshot_that_passes_the_limit_keeps_the_limit() {
        let pairs: Vec<(u64, u64)> = (0..=MAX_REGIONS as u64)
            .map(|index| (index * 0x2000, index * 0x2000 + 0x1000))
            .collect();
        assert_eq!(regions(&pairs).regions().len(), MAX_REGIONS);
    }

    #[test]
    fn a_snapshot_inside_the_limit_reports_no_truncation() {
        assert!(!regions(&[(0x1000, 0x2000)]).is_truncated());
    }

    #[test]
    fn a_region_states_its_size() {
        assert_eq!(Region::new(0x1000, 0x3000, false).bytes(), 0x2000);
    }

    #[test]
    fn a_region_holds_its_first_address_and_not_the_address_after_it() {
        let region = Region::new(0x1000, 0x2000, false);
        assert!(region.holds(0x1000) && !region.holds(0x2000));
    }
    #[test]
    fn a_region_that_became_writable_reads_as_changed() {
        // The attacker keeps the address and changes the protection only, so
        // the added-region rule reports nothing and this rule reports it.
        let start = regions(&[(0x1000, 0x2000)]);
        let now = writable(&[(0x1000, 0x2000)]);
        assert!(now.added_since(&start).is_empty());
        assert_eq!(now.now_writable_since(&start).len(), 1);
    }

    #[test]
    fn a_region_that_was_writable_at_start_reads_as_unchanged() {
        // A runtime that maps its own code cache writable before the baseline
        // is a clean control, and it stays clean on every later scan.
        let start = writable(&[(0x1000, 0x2000)]);
        assert!(
            writable(&[(0x1000, 0x2000)])
                .now_writable_since(&start)
                .is_empty()
        );
    }
}
