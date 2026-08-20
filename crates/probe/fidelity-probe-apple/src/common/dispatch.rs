//! The dispatch capability body that both Apple systems run.
//!
//! macOS and iOS carry the same Mach-O layout and the same loader, so the walk
//! and the rule live here once. Each system keeps an `impl` in a file of this
//! name, as [the module](super) states.

use fidelity_core::{DispatchTargets, Observation, Target};

use crate::sys;

/// What the capability reports when the image holds no readable table.
const NO_TABLE: &str = "the main image holds no symbol-pointer table";

/// The dispatch targets of the main image.
pub(crate) fn dispatch_targets() -> Observation<DispatchTargets> {
    let Some(raw) = sys::dispatch::read() else {
        // A static image, or one with no symbol-pointer section, holds no
        // dispatch target to watch. That is a gap in coverage, and never a
        // finding.
        return Observation::Unsupported { reason: NO_TABLE };
    };

    let targets = raw
        .targets
        .into_iter()
        .map(|target| Target::new(target.slot, target.value))
        .collect();
    Observation::Fact(DispatchTargets::new(targets, raw.bound))
}
