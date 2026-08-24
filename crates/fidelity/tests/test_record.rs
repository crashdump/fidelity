//! Tests that the test record states what the code actually claims.
//!
//! `docs/plan/05-verification.md` makes a missing control the thing that blocks
//! a platform from the supported label. That only works while the record and
//! the code agree, and nothing made them agree before this file.
//!
//! The failure it stops is quiet. A capability lands, its cell in the coverage
//! matrix turns to `yes`, `capability_matrix.rs` passes because the code is
//! real, and `tests/platform/README.md` never gains a row. The library then claims a
//! platform that no recorded control ever exercised.
//!
//! These rules read Markdown and Rust as text, for the reason that
//! `architecture.rs` states: a rule about the shape of the workspace has to see
//! the workspace.
//!
//! What the rules do not check: whether a row is true. A human runs each
//! control and writes down what happened, and no test can replace that. The
//! rules check that a row exists, names a real detector, names a real system,
//! and points at a control that is present.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

/// The systems that the coverage matrix names, in its column order.
///
/// The test record uses the same names, so a row binds to a cell.
const SYSTEMS: &[&str] = &["macOS", "iOS", "Windows", "Linux", "Android"];

/// The workspace root, from this crate's manifest.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the workspace root must resolve: {error}"))
}

/// Reads one file that a rule depends on.
fn read(relative: &str) -> String {
    let path = root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{relative} must exist: {error}"))
}

/// Splits one Markdown table line into its cells.
fn cells(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    Some(
        trimmed
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().trim_matches('`').to_owned())
            .collect(),
    )
}

/// The category that the matrix gives a capability that reports no finding.
const NO_CATEGORY: &str = "none";

/// What a row writes in its detector column when no detector reads it.
///
/// One capability answers no question and reports no finding, so it has no
/// detector and no hostile control. It still needs a row, because it still
/// needs a clean control.
const NO_DETECTOR: &str = "none";

/// One row of the test record: its capability, detector, and system.
struct Row {
    capability: String,
    detector: String,
    system: String,
}

/// Reads the detector coverage table out of the test record.
///
/// The table starts at the header whose first cell is `Capability`, and it ends
/// at the first line that is not part of a table. Every later table in the file
/// therefore stays out of these rules.
fn record() -> Vec<Row> {
    let text = read("tests/platform/README.md");
    let mut rows = Vec::new();
    let mut inside = false;

    for line in text.lines() {
        let Some(cells) = cells(line) else {
            if inside {
                break;
            }
            continue;
        };
        if cells.first().is_some_and(|first| first == "Capability") {
            assert_eq!(
                cells.len(),
                6,
                "the coverage table must hold its six columns"
            );
            inside = true;
            continue;
        }
        if !inside || cells.iter().all(|cell| cell.starts_with("---")) {
            continue;
        }
        rows.push(Row {
            capability: cells[0].clone(),
            detector: cells[1].clone(),
            system: cells[2].clone(),
        });
    }

    assert!(!rows.is_empty(), "the test record must hold rows");
    rows
}

/// Every `yes` cell of the coverage matrix, as a capability and a system.
///
/// This reads the same table that `capability_matrix.rs` reads. That file binds
/// a cell to code, and this one binds the same cell to a recorded control.
fn implemented() -> Vec<(String, String)> {
    let text = read("docs/plan/06-delivery.md");
    let mut found = Vec::new();
    let mut inside = false;

    for line in text.lines() {
        let Some(cells) = cells(line) else {
            inside = false;
            continue;
        };
        if cells.first().is_some_and(|first| first == "Capability") {
            inside = true;
            continue;
        }
        if !inside || cells.iter().all(|cell| cell.starts_with("---")) {
            continue;
        }
        for (index, cell) in cells[2..].iter().enumerate() {
            if cell == "yes" {
                found.push((cells[0].clone(), SYSTEMS[index].to_owned()));
            }
        }
    }

    assert!(!found.is_empty(), "the matrix must claim one capability");
    found
}

/// The category that the coverage matrix gives each capability.
fn categories() -> BTreeMap<String, String> {
    let text = read("docs/plan/06-delivery.md");
    let mut found = BTreeMap::new();
    let mut inside = false;

    for line in text.lines() {
        let Some(cells) = cells(line) else {
            inside = false;
            continue;
        };
        if cells.first().is_some_and(|first| first == "Capability") {
            inside = true;
            continue;
        }
        if !inside || cells.iter().all(|cell| cell.starts_with("---")) {
            continue;
        }
        found.insert(cells[0].clone(), cells[1].clone());
    }

    assert!(!found.is_empty(), "the matrix must hold a capability");
    found
}

/// Every detector name that `fidelity-detect` declares.
///
/// A detector names itself in its `Detector::new` call, so the rule reads that
/// rather than a second list that could drift.
fn detectors() -> BTreeSet<String> {
    fn walk(path: &PathBuf, found: &mut BTreeSet<String>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap_or_default();
            for (index, _) in text.match_indices("Detector::new(") {
                let rest = &text[index..];
                let Some(open) = rest.find('"') else { continue };
                let Some(close) = rest[open + 1..].find('"') else {
                    continue;
                };
                found.insert(rest[open + 1..open + 1 + close].to_owned());
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(&root().join("crates/fidelity-detect/src"), &mut found);
    assert!(!found.is_empty(), "the workspace must declare a detector");
    found
}

/// What the capability column reads for the one detector that no probe answers.
///
/// `UiAbuse` has no capability and no platform row, because no operating system
/// answers the question. `docs/plan/04-detectors-and-platforms.md` holds the
/// measurement, and `06-delivery.md` states that the matrix therefore skips it.
/// The rules below exempt this row by name, so nothing else can slip past them.
const HOST_FED: &str = "none, the host reports";

#[test]
fn every_implemented_capability_holds_a_record_row() {
    // The rule that matters. A `yes` cell states that the platform answers, and
    // `05-verification.md` states that only real clean and hostile controls
    // makes that claim legitimate. Without this rule the two documents can
    // disagree in silence, and the release gate reads both.
    let rows = record();
    let mut checked = 0_usize;
    for (capability, system) in implemented() {
        assert!(
            rows.iter()
                .any(|row| row.capability == capability && row.system == system),
            "the matrix reads yes for {capability} on {system}, and the test record holds no \
             row for it"
        );
        checked += 1;
    }
    assert!(checked > 0, "the rule must check a capability");
}

#[test]
fn every_record_row_names_a_detector_that_exists() {
    // A row for a detector that no crate declares records a control that
    // nothing runs. It also catches a detector that was renamed and left a
    // stale row behind.
    let declared = detectors();
    for row in record() {
        if row.detector == NO_DETECTOR {
            continue;
        }
        assert!(
            declared.contains(&row.detector),
            "the test record names {}, and no detector declares that name",
            row.detector
        );
    }
}

#[test]
fn a_row_reads_none_only_where_the_capability_reports_no_finding() {
    // The escape hatch above needs a bound. Without this rule, any row could
    // write `none` in its detector column and skip the check entirely, which
    // is exactly the silence the whole file exists to stop.
    let categories = categories();
    let mut checked = 0_usize;
    for row in record() {
        if row.detector != NO_DETECTOR {
            continue;
        }
        assert_eq!(
            categories.get(&row.capability).map(String::as_str),
            Some(NO_CATEGORY),
            "the {} capability reports a finding, so its row must name a detector",
            row.capability
        );
        checked += 1;
    }
    assert!(checked > 0, "the rule must check a row");
}

#[test]
fn every_record_row_names_a_system_that_the_matrix_holds() {
    // The record and the matrix have to use one vocabulary, or the rule above
    // silently matches nothing.
    for row in record() {
        if row.capability == HOST_FED {
            continue;
        }
        assert!(
            SYSTEMS.contains(&row.system.as_str()),
            "the test record names the system {}, and the matrix holds {SYSTEMS:?}",
            row.system
        );
    }
}

#[test]
fn every_record_row_names_a_capability_that_the_matrix_holds() {
    let known: BTreeSet<String> = implemented()
        .into_iter()
        .map(|(capability, _)| capability)
        .collect();
    let mut host_fed = 0_usize;
    for row in record() {
        if row.capability == HOST_FED {
            host_fed += 1;
            continue;
        }
        assert!(
            known.contains(&row.capability),
            "the test record names the {} capability, and no matrix cell reads yes for it",
            row.capability
        );
    }
    // The exemption is one row, and it must stay one row. A second one would
    // mean a category quietly left the platform axis without a measurement
    // saying that no operating system answers it.
    assert_eq!(
        host_fed, 1,
        "exactly one record row takes a host report, and the matrix holds no cell for it"
    );
}

#[test]
fn the_harness_names_every_control() {
    // The rule in the other direction. A control that the harness never
    // mentions is a control that nobody re-runs, and the harness is what turns
    // this record from a hand-written claim into a generated one.
    //
    // The harness either runs a control or records that a person runs it. This
    // rule stops the third case, which is silence.
    let harness = read("tests/platform/run.sh");
    let directory = root().join("tests/platform/controls");
    let Ok(entries) = fs::read_dir(&directory) else {
        panic!("tests/platform/controls must exist");
    };
    let mut checked = 0_usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            harness.contains(name.as_ref()),
            "tests/platform/controls/{name} exists, and tests/platform/run.sh names no control by that name"
        );
        checked += 1;
    }
    assert!(checked > 0, "the rule must check a control");
}

#[test]
fn each_open_hardware_arm_has_a_harness_control() {
    let harness = read("tests/platform/run.sh");
    let controls = [
        ("Linux", "machine-hardware-linux"),
        ("Windows", "machine-hardware-windows"),
        ("Android", "machine-hardware-android"),
    ];

    for (system, control) in controls {
        assert!(
            harness.contains(&format!("run {system} {control} ")),
            "the harness must run {control} on a verified physical {system} host"
        );
    }
}

#[test]
fn the_android_harness_runs_both_emulator_architectures() {
    let shell = read("tests/platform/run.sh");
    let gradle = read("crates/probe/fidelity-probe-android/android/build.gradle.kts");
    let architectures = [
        ("aarch64-linux-android", "arm64-v8a"),
        ("x86_64-linux-android", "x86_64"),
    ];

    for (target, abi) in architectures {
        assert!(
            shell.contains(&format!("ANDROID_TARGET={target}")),
            "the platform harness must select {target}"
        );
        assert!(
            gradle.contains(target) && gradle.contains(abi),
            "the instrumented harness must package {abi} from {target}"
        );
    }
}

#[test]
fn every_control_that_the_record_names_exists() {
    // A record that points at a control nobody can find is a record of nothing.
    // The controls are the part that makes a claim reproducible after the
    // machine that produced it is gone.
    let text = read("tests/platform/README.md");
    let mut checked = 0_usize;
    for (index, _) in text.match_indices("controls/") {
        let rest = &text[index..];
        let end = rest
            .find(|character: char| {
                !character.is_ascii_alphanumeric() && !"controls/._-".contains(character)
            })
            .unwrap_or(rest.len());
        let named = &rest[..end];
        // The record also names the directory itself, in prose. A file carries
        // an extension, and the directory does not.
        if !named.contains('.') {
            continue;
        }
        assert!(
            root().join("tests/platform").join(named).is_file(),
            "the test record names tests/platform/{named}, and no such file exists"
        );
        checked += 1;
    }
    assert!(checked > 0, "the record must name a control");
}

#[test]
fn the_gate_takes_its_target_list_from_the_harness() {
    // The harness cross-builds every supported target, and the gate installs
    // them. A target that the list gains and the gate lacks fails there as a
    // missing standard library, and that message names neither the target nor
    // the toolchain that lacks it. It happened on 2026-08-18, so this rule
    // stops the second copy rather than the symptom.
    let harness = read("tests/platform/run.sh");
    let Some(line) = harness.lines().find(|line| line.starts_with("TARGETS=")) else {
        panic!("tests/platform/run.sh must state its target list on a TARGETS= line");
    };
    let targets: Vec<&str> = line
        .trim_start_matches("TARGETS=")
        .trim_matches('"')
        .split_whitespace()
        .collect();
    assert!(targets.len() > 1, "the rule must check a target");

    let gate = read(".github/workflows/ci.yml");
    assert!(
        gate.contains("run.sh --targets"),
        "the gate must ask tests/platform/run.sh for the target list"
    );
    for target in targets {
        assert!(
            !gate.contains(target),
            "the gate names {target} itself, and that copy drifts from tests/platform/run.sh"
        );
    }
}
