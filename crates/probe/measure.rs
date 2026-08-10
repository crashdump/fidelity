//! The measurement loop that the `cost` example of each probe crate runs.
//!
//! This file belongs to no crate. Each `cost` example includes it with
//! `#[path]`, because the three examples measure different capabilities and
//! share only the loop. A copy in each crate would drift, and one number that
//! a different loop produced is not comparable with the others.
//!
//! Every example reads through `&dyn Environment`, and hides that reference
//! behind `black_box`. Both parts are necessary. The engine holds
//! `Box<dyn Environment>`, so an indirect call is what a host pays. It is also
//! the only form the optimizer cannot lift out of the loop: a read that
//! touches static memory only, such as the iOS signature walk, otherwise
//! measures 98 ns because it runs once for the whole loop.
//!
//! [State and budgets](../../docs/plan/07-state-and-budgets.md) records what
//! the examples print.

use std::time::{Duration, Instant};

/// How long one measurement runs.
///
/// A fixed run count cannot serve both ends of the range. A tracer read costs
/// microseconds and an Android identity read costs milliseconds, so the count
/// follows the clock instead.
const BOUND: Duration = Duration::from_millis(200);

/// The smallest number of runs that a mean rests on.
const RUNS: u32 = 10;

/// Names the columns that the lines below print.
pub(crate) fn heading() -> String {
    format!("{:<16}{:>12}  {}", "read", "each", "runs")
}

/// Prints what the first call costs.
///
/// `start()` pays this one. A framework that fills a cache once charges the
/// first caller for it, so the first call and the later calls are different
/// numbers and the budget states both.
pub(crate) fn first(label: &str, call: impl FnOnce()) {
    let start = Instant::now();
    call();
    println!("{label:<16}{:>12.1?}  first", start.elapsed());
}

/// Prints the mean cost of one call, over as many runs as the bound allows.
pub(crate) fn report(label: &str, mut call: impl FnMut()) {
    let start = Instant::now();
    let mut runs = 0_u32;
    while runs < RUNS || start.elapsed() < BOUND {
        call();
        runs = runs.saturating_add(1);
    }
    println!("{label:<16}{:>12.1?}  {runs}", start.elapsed() / runs);
}
