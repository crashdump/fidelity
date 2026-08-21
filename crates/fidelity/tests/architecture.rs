//! Tests that the workspace keeps the shape its documents promise.
//!
//! Every rule here is a claim that `docs/` already makes. A claim that no test
//! checks decays, so each one runs on every change.
//!
//! The tests read manifests and sources as text. That is deliberate: a rule
//! about the shape of the workspace has to see the workspace, and a compile
//! error would arrive too late for the rules about dependency direction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root, from this crate's manifest.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("the workspace root must resolve: {error}"))
}

/// Every crate in the workspace, as a name and a manifest.
fn crates() -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for directory in ["crates", "crates/probe"] {
        let path = root().join(directory);
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let manifest = entry.path().join("Cargo.toml");
            if let Ok(text) = fs::read_to_string(&manifest) {
                let name = entry.file_name().to_string_lossy().into_owned();
                found.insert(name, text);
            }
        }
    }
    assert!(!found.is_empty(), "the workspace must hold crates");
    found
}

/// Every dependency that one manifest declares, by name.
///
/// The root manifest states each internal path and version once, so a crate
/// manifest writes `name.workspace = true` and holds no path at all. A rule
/// that searched a manifest for a path would pass for that reason alone, and
/// it would never fail again. This reads the declared names, and it sees the
/// plain form and the inherited form alike.
fn declared_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
            // `[workspace.dependencies]`, and a target section all end alike.
            inside = line.ends_with("dependencies]");
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        // `serde = { ... }` states the name alone. `serde.workspace = true`
        // states the name and one field, so the name ends at the first dot.
        let name = key
            .trim()
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_matches('"');
        if !name.is_empty() {
            found.insert(name.to_owned());
        }
    }
    found
}

/// Every Rust source file under one directory.
fn sources(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    found
}

/// Reports whether a crate is a platform probe.
fn is_probe(name: &str) -> bool {
    name.starts_with("fidelity-probe-")
}

#[test]
fn a_probe_crate_never_imports_a_detector_or_the_engine() {
    // ADR-0001 states that Cargo enforces the probe and detector separation.
    // Without this test the claim rests on nobody making the mistake.
    for (name, manifest) in crates() {
        if !is_probe(&name) {
            continue;
        }
        let declared = declared_dependencies(&manifest);
        for forbidden in ["fidelity-detect", "fidelity-engine", "fidelity-macros"] {
            assert!(
                !declared.contains(forbidden),
                "{name} depends on {forbidden}, and a probe must report facts only"
            );
        }
    }
}

#[test]
fn a_probe_crate_never_depends_on_the_facade() {
    // The facade depends on the probes. The reverse would be a cycle, and it
    // would let platform code reach the policy that it must not know about.
    for (name, manifest) in crates() {
        if is_probe(&name) {
            assert!(
                !declared_dependencies(&manifest).contains("fidelity"),
                "{name} depends on the facade, which inverts the layering"
            );
        }
    }
}

#[test]
fn only_a_probe_crate_writes_unsafe_code() {
    // `CLAUDE.md` section 8 states that all platform `unsafe` stays in the
    // probe crates. Every other crate proves it with `forbid(unsafe_code)`.
    for (name, _) in crates() {
        if is_probe(&name) || name == "fidelity-macros" {
            continue;
        }
        let directory = root().join("crates").join(&name).join("src");
        let library = directory.join("lib.rs");
        let text = fs::read_to_string(&library)
            .unwrap_or_else(|error| panic!("{name} must hold src/lib.rs: {error}"));
        assert!(
            text.contains("#![forbid(unsafe_code)]"),
            "{name} does not forbid unsafe code"
        );
    }
}

#[test]
fn unsafe_code_stays_inside_the_boundary_module() {
    // Every probe crate keeps its `unsafe` under `sys/`, so one reviewer reads
    // one directory. A safe wrapper is what the rest of the crate calls.
    for (name, _) in crates() {
        if !is_probe(&name) {
            continue;
        }
        let source = root().join("crates/probe").join(&name).join("src");
        for file in sources(&source) {
            let outside_boundary = !file.components().any(|part| part.as_os_str() == "sys");
            let text = fs::read_to_string(&file).unwrap_or_default();
            let writes_unsafe = text.contains("unsafe {") || text.contains("unsafe extern");
            assert!(
                !(outside_boundary && writes_unsafe),
                "{} writes unsafe code outside the sys boundary",
                file.display()
            );
        }
    }
}

#[test]
fn no_crate_takes_a_remote_network_dependency() {
    // ADR-0004 prohibits a remote network path. A dependency is the way one
    // would arrive without anybody writing a socket call.
    const FORBIDDEN: &[&str] = &[
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "surf",
        "isahc",
        "attohttpc",
        "rustls",
        "native-tls",
        "openssl",
        "tokio-tungstenite",
        "quinn",
    ];
    // The root manifest states every shared dependency, so it is the first
    // place such a crate would arrive. It is read here beside the crates.
    let mut manifests = crates();
    let root = fs::read_to_string(root().join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("the workspace manifest must exist: {error}"));
    manifests.insert("the workspace".to_owned(), root);

    for (name, manifest) in manifests {
        let declared = declared_dependencies(&manifest);
        for dependency in FORBIDDEN {
            assert!(
                !declared.contains(*dependency),
                "{name} depends on {dependency}, and ADR-0004 prohibits a remote network client"
            );
        }
    }
}

#[test]
fn an_external_crate_arrives_only_through_a_feature_that_is_off() {
    // `06-delivery.md` states that a default build of the workspace resolves to
    // no external crate, and that property is what lets a security library be
    // read end to end. Two optional dependencies now exist, `serde` and
    // `tracing`, so the property holds only while every external crate stays
    // optional. One that arrives without `optional = true` breaks it silently,
    // because a build still succeeds.
    //
    // The rule reads the root manifest alone. Every crate states a shared
    // dependency there, and `declared_dependencies` above says why.
    let manifest = fs::read_to_string(root().join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("the workspace manifest must exist: {error}"));
    let internal: BTreeSet<String> = crates().into_keys().collect();
    let external: BTreeSet<String> = declared_dependencies(&manifest)
        .into_iter()
        .filter(|name| !internal.contains(name))
        .collect();
    assert!(
        !external.is_empty(),
        "the rule must check an external crate"
    );

    // Every crate that takes one must mark it optional, and not merely one of
    // them. A rule that accepted one `optional = true` anywhere would pass
    // while another crate took the same dependency outright.
    let mut checked = 0_usize;
    for (name, crate_manifest) in crates() {
        let mut inside = false;
        for line in crate_manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                inside = line.ends_with("dependencies]");
                continue;
            }
            if !inside || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            let declared = key.trim().split('.').next().unwrap_or_default();
            if !external.contains(declared) {
                continue;
            }
            assert!(
                line.contains("optional = true"),
                "{name} takes the external crate {declared} without optional = true, \
                 so a default build stopped resolving to no external crate"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the rule must check a declaration");
}

#[test]
fn a_platform_is_selected_by_its_target_and_never_by_a_feature() {
    // `06-delivery.md` states the rule. A feature is additive and global, so
    // one that a host forgets would silently drop protection.
    for (name, manifest) in crates() {
        if !is_probe(&name) {
            continue;
        }
        let declares_features = manifest
            .lines()
            .any(|line| line.trim_start().starts_with("[features]"));
        assert!(
            !declares_features,
            "{name} declares a feature, and a probe is selected by its target"
        );
    }
    let facade = crates()
        .get("fidelity")
        .cloned()
        .unwrap_or_else(|| panic!("the facade must exist"));
    assert!(
        facade.contains(
            "[target.'cfg(any(target_os = \"macos\", target_os = \"ios\"))'.dependencies]"
        ),
        "the facade must take each probe as a target dependency"
    );
}

#[test]
fn conditional_platform_code_stays_in_the_probes_and_one_seam() {
    // Platform code belongs to a probe crate. Something still has to map the
    // target to its probe, and `backend.rs` is that one seam. This test keeps
    // the seam from spreading: every other crate must compile the same source
    // on every target.
    //
    // The `cfg!` macro is a value, not a gate. Every arm of `cfg!` type-checks
    // everywhere, so `Platform::target()` stays portable and this rule only
    // reads the `#[cfg(...)]` attribute.
    const SEAM: &str = "backend.rs";

    for (name, _) in crates() {
        if is_probe(&name) {
            continue;
        }
        let source = root().join("crates").join(&name).join("src");
        for file in sources(&source) {
            if file.file_name().is_some_and(|leaf| leaf == SEAM) {
                continue;
            }
            let text = fs::read_to_string(&file).unwrap_or_default();
            let gates_on_target = text
                .lines()
                .filter(|line| line.trim_start().starts_with("#[cfg"))
                .any(|line| line.contains("target_os") || line.contains("target_arch"));
            assert!(
                !gates_on_target,
                "{} gates on the target. Platform code belongs in a probe crate, and {SEAM} \
                 is the only seam that selects one",
                file.display()
            );
        }
    }
}

#[test]
fn a_probe_crate_compiles_for_its_own_target_only() {
    // A probe crate is one operating system, and its name says so. The crate
    // condition is what keeps that true.
    //
    // The rule matters because of what it forces elsewhere: a pure reader
    // cannot live inside a probe crate, since the condition would let it be
    // tested on one target only. That is why `fidelity-formats` exists.
    for (name, _) in crates() {
        if !is_probe(&name) {
            continue;
        }
        let library = root().join("crates/probe").join(&name).join("src/lib.rs");
        let text = fs::read_to_string(&library)
            .unwrap_or_else(|error| panic!("{name} must hold src/lib.rs: {error}"));
        assert!(
            text.lines()
                .any(|line| line.starts_with("#![cfg(") && line.contains("target_os")),
            "{name} does not restrict itself to its own target"
        );
    }
}

#[test]
fn the_format_crate_holds_no_platform_code_and_no_dependency() {
    // `fidelity-formats` sits off the platform axis, so its tests run on any
    // machine. A target condition or a dependency would end that, and the
    // readers would silently become untestable away from their platform.
    let manifest = crates()
        .get("fidelity-formats")
        .cloned()
        .unwrap_or_else(|| panic!("the format crate must exist"));
    assert!(
        !manifest.contains("dependencies]"),
        "fidelity-formats takes a dependency, and a pure reader needs none"
    );

    let source = root().join("crates/fidelity-formats/src");
    for file in sources(&source) {
        let text = fs::read_to_string(&file).unwrap_or_default();
        assert!(
            !text.contains("target_os"),
            "{} names a target, and a pure reader must not",
            file.display()
        );
    }
}

#[test]
fn dispatch_boundaries_use_the_safe_format_readers() {
    let root = root();
    for platform in ["linux", "android"] {
        let file = root.join(format!(
            "crates/probe/fidelity-probe-{platform}/src/sys/dispatch.rs"
        ));
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{} must exist: {error}", file.display()));
        assert!(
            source.contains("fidelity_formats::elf")
                && !source.contains("struct Dyn")
                && !source.contains("struct Rela"),
            "{platform} must use the safe ELF reader"
        );
    }

    let apple = root.join("crates/probe/fidelity-probe-apple/src/sys/dispatch.rs");
    let source = fs::read_to_string(&apple)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", apple.display()));
    assert!(
        source.contains("fidelity_formats::macho::dispatch")
            && !source.contains("struct LoadCommand")
            && !source.contains("struct Section"),
        "Apple must use the safe Mach-O reader"
    );

    let image = root.join("crates/probe/fidelity-probe-apple/src/sys/image.rs");
    let source = fs::read_to_string(&image)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", image.display()));
    assert!(
        source.contains("fidelity_formats::macho::image")
            && !source.contains("struct LoadCommand")
            && !source.contains("struct SegmentCommand"),
        "Apple identity must use the safe Mach-O image reader"
    );

    let windows = root.join("crates/probe/fidelity-probe-windows/src/sys/dispatch.rs");
    let source = fs::read_to_string(&windows)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", windows.display()));
    assert!(
        source.contains("copy_readable_allocation") && !source.contains("from_raw_parts"),
        "Windows must copy readable image pages before the PE reader"
    );
}

#[test]
fn the_parser_attack_crate_stays_outside_the_production_workspace() {
    let manifest = fs::read_to_string(root().join("Cargo.toml"))
        .unwrap_or_else(|error| panic!("the workspace manifest must exist: {error}"));
    assert!(
        !manifest.lines().any(|line| line.trim() == "\"fuzz\","),
        "the parser attack crate must not enter the production workspace"
    );
}

#[test]
fn the_parser_attack_crate_owns_its_workspace() {
    let manifest = fs::read_to_string(root().join("fuzz/Cargo.toml"))
        .unwrap_or_else(|error| panic!("the parser attack manifest must exist: {error}"));
    assert!(
        manifest.lines().any(|line| line.trim() == "[workspace]"),
        "the parser attack crate must own an independent workspace"
    );
}

#[test]
fn each_parser_attack_target_has_a_workflow_and_a_seed() {
    let root = root();
    let manifest = fs::read_to_string(root.join("fuzz/Cargo.toml"))
        .unwrap_or_else(|error| panic!("the parser attack manifest must exist: {error}"));
    let workflow = fs::read_to_string(root.join(".github/workflows/fuzz.yml"))
        .unwrap_or_else(|error| panic!("the parser attack workflow must exist: {error}"));
    let mut targets = Vec::new();
    let mut reads_name = false;
    for line in manifest.lines().map(str::trim) {
        if line == "[[bin]]" {
            reads_name = true;
            continue;
        }
        if reads_name && line.starts_with("name = \"") {
            targets.push(line.trim_start_matches("name = \"").trim_end_matches('"'));
            reads_name = false;
        }
    }

    assert_eq!(
        targets.len(),
        14,
        "the plan requires 14 parser attack targets"
    );
    for target in targets {
        assert!(
            workflow.contains(&format!("          - {target}")),
            "the parser attack workflow omits {target}"
        );
        assert!(
            root.join("fuzz/corpus").join(target).join("seed").is_file(),
            "the parser attack target {target} has no seed"
        );
    }
}

#[test]
fn the_tauri_adapter_stays_outside_the_production_workspace() {
    let manifest = fs::read_to_string(root().join("bindings/tauri-plugin-fidelity/Cargo.toml"))
        .unwrap_or_else(|error| panic!("the Tauri adapter manifest must exist: {error}"));
    assert!(
        manifest.lines().any(|line| line.trim() == "[workspace]"),
        "the Tauri adapter must own an independent workspace"
    );

    let source = fs::read_to_string(root().join("bindings/tauri-plugin-fidelity/src/lib.rs"))
        .unwrap_or_else(|error| panic!("the Tauri adapter library must exist: {error}"));
    assert!(
        !source.contains("#[tauri::command]") && !source.contains("invoke_handler"),
        "the Tauri adapter must expose no WebView command"
    );
}

#[test]
fn the_tauri_adapter_matches_its_small_public_surface() {
    let source = fs::read_to_string(root().join("bindings/tauri-plugin-fidelity/src/lib.rs"))
        .unwrap_or_else(|error| panic!("the Tauri adapter library must exist: {error}"));
    let surface: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("pub fn ")
                || line.starts_with("pub trait ")
                || line.starts_with("fn fidelity_handle(")
                || line.starts_with("fn ensure_fidelity_allowed(")
        })
        .collect();
    assert_eq!(
        surface,
        [
            "pub fn init<R: Runtime>(builder: fidelity::Builder) -> TauriPlugin<R> {",
            "pub trait FidelityExt<R: Runtime>: Manager<R> {",
            "fn fidelity_handle(&self) -> fidelity::Handle {",
            "fn ensure_fidelity_allowed(&self) -> Result<(), fidelity::Denied> {",
        ]
    );
}

#[test]
fn the_package_gate_compares_two_archive_sets() {
    let source = fs::read_to_string(root().join("tests/package.sh"))
        .unwrap_or_else(|error| panic!("the package gate must exist: {error}"));
    assert!(
        source.contains("package-first")
            && source.contains("package-second")
            && source.contains("cmp"),
        "the package gate must compare two independent archive sets"
    );
}

#[test]
fn the_android_cost_measurement_reads_what_one_worker_cycle_reads() {
    // The instrumented harness measures a worker cycle and names its own read
    // list, and `Detectors::scan_cheap` owns the real one. The two drifted
    // apart until 2026-08-20: the worker ran eight detectors and the
    // measurement stopped at six, so `system_build` and `machine_host` went
    // unmeasured on every run and the 20 ms ceiling covered neither. A review
    // found that, and no test could have, because nothing compared the two.
    //
    // One detector reads once, so the counts must match. A new detector
    // therefore fails this until the measurement grows with it.
    let engine = fs::read_to_string(root().join("crates/fidelity-detect/src/lib.rs"))
        .unwrap_or_else(|_| panic!("the detector crate must hold lib.rs"));
    let Some(cheap) = engine.split_once("pub fn scan_cheap") else {
        panic!("the detector crate must hold scan_cheap");
    };
    let Some(body) = cheap.1.split_once("\n    }") else {
        panic!("scan_cheap must end");
    };
    let detectors = body.0.matches("guarded(").count();
    assert!(detectors > 0, "scan_cheap must run a detector");

    let harness = root().join("crates/probe/fidelity-probe-android/android");
    let kotlin = fs::read_to_string(harness.join("src/main/kotlin/fidelity/probe/Harness.kt"))
        .unwrap_or_else(|_| panic!("the harness must hold Harness.kt"));
    let Some(list) = kotlin.split_once("val READS = arrayOf(") else {
        panic!("the harness must name the reads of one cycle");
    };
    let Some(names) = list.1.split_once(')') else {
        panic!("the read list must end");
    };
    let reads = names.0.matches('"').count() / 2;

    let rust = fs::read_to_string(harness.join("harness/src/lib.rs"))
        .unwrap_or_else(|_| panic!("the harness must hold lib.rs"));
    let Some(cycle) = rust.split_once("fn Java_fidelity_probe_Harness_cycleCostMicros") else {
        panic!("the harness must measure one cycle");
    };
    let Some(calls) = cycle.1.split_once("\n}") else {
        panic!("the cycle must end");
    };
    let measured = calls.0.matches("black_box(probe.").count();

    assert_eq!(
        detectors, reads,
        "the worker runs {detectors} detectors and the harness names {reads} reads"
    );
    assert_eq!(
        detectors, measured,
        "the worker runs {detectors} detectors and the measured cycle makes {measured} reads"
    );
}

#[test]
fn every_probe_crate_repeats_the_same_shape() {
    // `06-delivery.md` states that each probe holds `sys/` for the boundary,
    // then one module for each capability. A new probe that invents another
    // shape makes the platform axis unreadable.
    for (name, _) in crates() {
        if !is_probe(&name) {
            continue;
        }
        let source = root().join("crates/probe").join(&name).join("src");
        assert!(
            source.join("lib.rs").is_file(),
            "{name} must hold src/lib.rs"
        );
        assert!(
            source.join("sys").is_dir(),
            "{name} must hold src/sys/ for its operating-system boundary"
        );
    }
}
