//! Tests that each probe answers the capabilities that the matrix declares.
//!
//! `docs/plan/06-delivery.md` holds one row for each capability and one column
//! for each platform. That table is the declaration, and this file is what
//! makes it true.
//!
//! The table needs a test because a capability trait defaults to
//! `Unsupported`. The default is what lets a new capability arrive without a
//! change to five probe crates. It also means a probe that answers nothing
//! still compiles, so a gap stays silent. The table states the intent, and
//! these rules compare it against the code on every change.
//!
//! The tests read the document and the sources as text, for the reason that
//! `architecture.rs` states: a rule about the shape of the workspace has to see
//! the workspace.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Where each platform column keeps its capability modules.
///
/// A probe that holds one system keeps them at the crate root. The Apple crate
/// holds two systems, so each one takes its own directory.
const SYSTEMS: &[(&str, &str)] = &[
    ("macOS", "crates/probe/fidelity-probe-apple/src/macos"),
    ("iOS", "crates/probe/fidelity-probe-apple/src/ios"),
    ("Windows", "crates/probe/fidelity-probe-windows/src"),
    ("Linux", "crates/probe/fidelity-probe-linux/src"),
    ("Android", "crates/probe/fidelity-probe-android/src"),
];

/// The markers that one cell may hold.
const MARKERS: &[&str] = &["yes", "plan", "no"];

/// The category of a capability that reports no finding.
const NO_CATEGORY: &str = "none";

/// Where the capability traits live.
const CAPABILITY_DIRECTORY: &str = "crates/fidelity-core/src/capability";

/// One row of the coverage matrix.
struct Row {
    /// The capability name, which is also its file name and its trait name.
    capability: String,
    /// The category that the capability reports, or `none`.
    category: String,
    /// One cell for each entry of [`SYSTEMS`], in the same order.
    cells: Vec<String>,
}

/// The workspace root, from this crate's manifest.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the workspace root must resolve: {error}"))
}

/// Splits one Markdown table line into its cells.
///
/// Returns `None` for a line that is not part of a table, which is how the
/// reader below knows that the matrix ended.
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

/// Reads the coverage matrix out of the delivery document.
///
/// The column check runs here, so every rule below inherits it. A column that
/// moves or disappears fails the whole file rather than one test.
fn matrix() -> Vec<Row> {
    let path = root().join("docs/plan/06-delivery.md");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the delivery document must exist: {error}"));

    let width = SYSTEMS.len() + 2;
    let mut rows = Vec::new();
    let mut inside = false;

    for line in text.lines() {
        let Some(cells) = cells(line) else {
            inside = false;
            continue;
        };

        if cells.first().is_some_and(|first| first == "Capability") {
            assert_eq!(
                cells.len(),
                width,
                "the coverage matrix must hold one column for each of the {} probes",
                SYSTEMS.len()
            );
            for (index, (platform, _)) in SYSTEMS.iter().enumerate() {
                assert_eq!(
                    &cells[index + 2],
                    platform,
                    "column {index} must name {platform}, so every platform stays checked"
                );
            }
            inside = true;
            continue;
        }

        if !inside || cells.iter().all(|cell| cell.starts_with("---")) {
            continue;
        }

        assert_eq!(
            cells.len(),
            width,
            "the {} row must hold one cell for each platform",
            cells.first().map_or("unnamed", String::as_str)
        );
        rows.push(Row {
            capability: cells[0].clone(),
            category: cells[1].clone(),
            cells: cells[2..].to_vec(),
        });
    }

    assert!(!rows.is_empty(), "the coverage matrix must hold rows");
    rows
}

/// The trait name that one capability row names.
fn trait_name(capability: &str) -> String {
    let mut characters = capability.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + characters.as_str()
    })
}

/// Every capability trait that `fidelity-core` declares today.
///
/// A row of the matrix may name a capability that no trait declares yet. The
/// rules that read the code apply to this set only.
fn declared() -> BTreeSet<String> {
    let directory = root().join(CAPABILITY_DIRECTORY);
    let entries = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("the capability directory must exist: {error}"));
    let mut found = BTreeSet::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let Some(stem) = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
            else {
                continue;
            };
            if stem != "mod" {
                found.insert(stem);
            }
        }
    }
    assert!(!found.is_empty(), "the workspace must declare a capability");
    found
}

/// The probe crate that one platform column belongs to.
fn probe_crate(directory: &str) -> &str {
    directory
        .split('/')
        .nth(2)
        .unwrap_or_else(|| panic!("{directory} must name a probe crate"))
}

/// Every Rust source of one crate, as one string.
fn crate_text(directory: &str) -> String {
    fn walk(path: &PathBuf, text: &mut String) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, text);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                text.push_str(&fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    let mut text = String::new();
    walk(&root().join(directory), &mut text);
    text
}

#[test]
fn every_probe_crate_holds_a_column() {
    // A sixth probe crate with no column would sit outside every rule below.
    let path = root().join("crates/probe");
    let entries = fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("the probe directory must exist: {error}"));
    for entry in entries.flatten() {
        if !entry.path().join("Cargo.toml").is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            SYSTEMS
                .iter()
                .any(|(_, directory)| probe_crate(directory) == name),
            "{name} holds no column in the coverage matrix, so no rule checks it"
        );
    }
}

#[test]
fn a_probe_that_holds_platform_code_reaches_the_runtime() {
    // A `yes` cell states that the platform answers. It answers nothing while
    // the seam does not construct the probe, because `start()` then returns
    // `PlatformUnavailable` and the capability never runs. The seam is one
    // file, so the rule reads it.
    let seam = fs::read_to_string(root().join("crates/fidelity/src/backend.rs"))
        .unwrap_or_else(|error| panic!("the platform seam must exist: {error}"));
    let manifest = fs::read_to_string(root().join("crates/fidelity/Cargo.toml"))
        .unwrap_or_else(|error| panic!("the facade manifest must exist: {error}"));
    let mut checked = 0_usize;
    for row in matrix() {
        for (index, cell) in row.cells.iter().enumerate() {
            if cell != "yes" {
                continue;
            }
            let (platform, directory) = SYSTEMS[index];
            let name = probe_crate(directory);
            assert!(
                seam.contains(&name.replace('-', "_")),
                "the matrix reads yes for {} on {platform}, so backend.rs must construct {name}",
                row.capability
            );
            // The seam alone is not enough. Each arm carries a target
            // condition, so an arm whose crate the manifest never names still
            // builds everywhere except the platform it serves.
            assert!(
                manifest.contains(name),
                "the matrix reads yes for {} on {platform}, so the facade must take {name} as a \
                 target dependency",
                row.capability
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the rule must check a platform");
}

#[test]
fn the_matrix_holds_a_row_for_every_capability_trait() {
    // A new trait with no row would answer `Unsupported` on all five platforms
    // and no document would say so.
    let rows = matrix();
    for capability in declared() {
        assert!(
            rows.iter().any(|row| row.capability == capability),
            "the coverage matrix holds no row for the {capability} capability"
        );
    }
}

#[test]
fn every_cell_holds_a_known_marker() {
    // The rules below read the markers, so an unknown one must fail loudly
    // rather than pass through as a cell that nothing checks.
    for row in matrix() {
        for (index, cell) in row.cells.iter().enumerate() {
            assert!(
                MARKERS.contains(&cell.as_str()),
                "the {} row reads \"{cell}\" for {}, and a cell holds one of {MARKERS:?}",
                row.capability,
                SYSTEMS[index].0
            );
        }
    }
}

#[test]
fn each_capability_file_declares_one_trait_of_its_own_name() {
    // The matrix maps one row name to one file name and to one trait name.
    // That map holds only while a file declares one trait, and the names agree.
    let mut checked = 0_usize;
    for capability in declared() {
        let file = root()
            .join(CAPABILITY_DIRECTORY)
            .join(format!("{capability}.rs"));
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{} must exist: {error}", file.display()));
        let declarations: Vec<&str> = text
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("pub trait "))
            .collect();
        assert_eq!(
            declarations.len(),
            1,
            "{} must declare one capability trait",
            file.display()
        );
        let wanted = format!("pub trait {}", trait_name(&capability));
        assert!(
            declarations[0].starts_with(&wanted),
            "{} must declare `{wanted}`, because the matrix derives the name from the row",
            file.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "the rule must check a capability");
}

#[test]
fn an_implemented_capability_holds_platform_code() {
    // A `yes` cell claims real platform code. Without this rule the table could
    // claim a capability that only the trait default answers, which is the
    // false clean result that the product contract prohibits.
    let mut checked = 0_usize;
    for row in matrix() {
        for (index, cell) in row.cells.iter().enumerate() {
            if cell != "yes" {
                continue;
            }
            let (platform, directory) = SYSTEMS[index];
            let file = root()
                .join(directory)
                .join(format!("{}.rs", row.capability));
            assert!(
                file.is_file(),
                "the matrix reads yes for {} on {platform}, so {} must hold the code",
                row.capability,
                file.display()
            );
            let wanted = format!("impl {} for", trait_name(&row.capability));
            let text = fs::read_to_string(&file).unwrap_or_default();
            assert!(
                text.contains(&wanted),
                "{} must hold `{wanted}`",
                file.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the matrix must claim one capability at least");
}

#[test]
fn a_capability_that_is_not_yes_holds_no_platform_code() {
    // The other direction. Code that lands while its cell still reads `plan`
    // makes the table understate the library, and the release gate reads the
    // table. A `no` cell that gains code is a stronger error: the platform was
    // supposed to be unable to answer.
    for row in matrix() {
        for (index, cell) in row.cells.iter().enumerate() {
            if cell == "yes" {
                continue;
            }
            let (platform, directory) = SYSTEMS[index];
            let file = root()
                .join(directory)
                .join(format!("{}.rs", row.capability));
            assert!(
                !file.is_file(),
                "{} holds code, so the matrix must read yes for {} on {platform}",
                file.display(),
                row.capability
            );
        }
    }
}

#[test]
fn a_capability_that_reads_no_holds_an_empty_impl() {
    // A `no` cell states that the platform cannot answer, and that is a
    // decision somebody made. The trait default already reports `Unsupported`,
    // so a probe that stayed silent would behave the same way, and a reader
    // could not tell a decided gap from a forgotten one. The empty `impl` is
    // where the decision and its reason live.
    let mut checked = 0_usize;
    for row in matrix() {
        if !declared().contains(&row.capability) {
            continue;
        }
        for (index, cell) in row.cells.iter().enumerate() {
            if cell != "no" {
                continue;
            }
            let (platform, directory) = SYSTEMS[index];
            let wanted = format!("impl {} for", trait_name(&row.capability));
            assert!(
                crate_text(directory).contains(&wanted),
                "the matrix reads no for {} on {platform}, so {directory} must hold `{wanted}`",
                row.capability
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "the matrix must hold a no cell that this reads"
    );
}

#[test]
fn every_capability_that_reports_a_finding_has_a_detector() {
    // A capability that no detector reads never reaches the host's snapshot,
    // so the platform code would run and report nothing.
    //
    // The rule looks for the bound that ADR-0008 states, so it also keeps
    // detectors on static dispatch with the `?Sized` bound that lets
    // `&dyn Environment` pass. ADR-0008 names the bound and not one syntax, so
    // the rule accepts the `impl Trait` form and the type-parameter form.
    let detectors = crate_text("crates/fidelity-detect/src");
    let mut checked = 0_usize;
    for row in matrix() {
        if row.category == NO_CATEGORY || !declared().contains(&row.capability) {
            continue;
        }
        let bound = format!("{} + ?Sized", trait_name(&row.capability));
        let forms = [format!("impl {bound}"), format!(": {bound}")];
        assert!(
            forms.iter().any(|form| detectors.contains(form)),
            "no detector takes `{bound}`, so nothing reports the {} capability",
            row.capability
        );
        checked += 1;
    }
    assert!(checked > 0, "the rule must check a capability");
}
