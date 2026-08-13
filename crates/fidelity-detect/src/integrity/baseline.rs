use fidelity_core::{Baseline, CodeRegions, Observation, Region};
use fidelity_types::{BoundedText, Category, Detector, Evidence, Finding, Outcome, SignalStrength};

/// The process maps executable code that it did not map at start.
pub const RUNTIME_BASELINE: Detector =
    Detector::new(5, "integrity.runtime_baseline", Category::Integrity);

/// The strength of a region that appeared after start.
///
/// `Medium`. The evidence is direct, because the region was not there when the
/// process started and something mapped it since. Measured on macOS 26: a
/// JavaScript engine compiles inside a pool that it reserved before the
/// baseline, so a running compiler adds nothing here.
///
/// One benign case keeps it below `High`. An application may load a plugin, a
/// driver, or a locale after it starts, and each one maps code. The
/// [plan](../../../../docs/plan/04-detectors-and-platforms.md) names a late
/// legitimate load as a required clean control, and `High` waits for it.
const ADDED_STRENGTH: SignalStrength = SignalStrength::Medium;

/// The strength of a region that turned writable after start.
///
/// `Medium`, and for the same reason as a region that arrived. The evidence is
/// direct, because the process did not map that code writable at start.
///
/// A runtime that maps its own code cache writable before the baseline never
/// reports here, because the comparison states a change and not a state. One
/// benign case keeps it below `High`: a compiler may change the protection of
/// a pool that it owns after the process starts.
const OPENED_STRENGTH: SignalStrength = SignalStrength::Medium;

/// The reason a truncated snapshot states.
const TRUNCATED: &str = "the process maps more executable regions than a snapshot keeps";

/// The reason an absent baseline states.
const NO_BASELINE: &str = "this build captured no baseline at start";

/// Interprets whether the process mapped code after it started.
///
/// The baseline is the snapshot that `start()` captured. It is immutable, so a
/// later scan compares against the state of the process before the host ran
/// any of its own work.
pub(crate) fn runtime_baseline(
    environment: &(impl Baseline + ?Sized),
    baseline: Option<&CodeRegions>,
    now_unix_ms: u64,
) -> Outcome {
    let Some(baseline) = baseline else {
        return Outcome::Unsupported {
            reason: NO_BASELINE,
        };
    };

    // A truncated snapshot drops regions, so a later region may look new when
    // the baseline simply did not keep it. Fidelity states that rather than
    // reporting a finding that it cannot stand behind.
    if baseline.is_truncated() {
        return Outcome::Unsupported { reason: TRUNCATED };
    }

    match environment.code_regions() {
        Observation::Unsupported { reason } => Outcome::Unsupported { reason },
        Observation::Failed { detail } => health(detail, now_unix_ms),
        Observation::Fact(current) => {
            if current.is_truncated() {
                return Outcome::Unsupported { reason: TRUNCATED };
            }
            let added = current.added_since(baseline);
            if !added.is_empty() {
                let bytes: u64 = added.iter().map(Region::bytes).sum();
                return Outcome::Finding(Finding::new(
                    RUNTIME_BASELINE,
                    ADDED_STRENGTH,
                    Evidence::CodeAddedAfterStart {
                        detail: BoundedText::new(format!(
                            "executable memory that start did not map: {bytes} bytes, region count {}",
                            added.len()
                        )),
                    },
                    now_unix_ms,
                ));
            }

            // A region that changed protection keeps its first address, so the
            // rule above reports nothing for it. Code that turns writable is
            // what a patch needs before it lands, so the baseline states it.
            let opened = current.now_writable_since(baseline);
            if opened.is_empty() {
                return Outcome::Clean;
            }
            let bytes: u64 = opened.iter().map(Region::bytes).sum();
            Outcome::Finding(Finding::new(
                RUNTIME_BASELINE,
                OPENED_STRENGTH,
                Evidence::CodeMadeWritable {
                    detail: BoundedText::new(format!(
                        "executable memory that start did not map writable: {bytes} bytes, region count {}",
                        opened.len()
                    )),
                },
                now_unix_ms,
            ))
        }
    }
}

/// Builds the `Low` finding that a failed probe produces.
///
/// Fidelity never converts a probe error into a clean result.
fn health(detail: BoundedText, now_unix_ms: u64) -> Outcome {
    Outcome::Finding(Finding::new(
        RUNTIME_BASELINE,
        SignalStrength::Low,
        Evidence::DetectorHealth { detail },
        now_unix_ms,
    ))
}
