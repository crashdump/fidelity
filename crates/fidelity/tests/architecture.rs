//! Tests that the workspace keeps the shape its documents promise.
//!
//! Every rule here is a claim that `docs/` already makes. A claim that no test
//! checks decays, so each one runs on every change.
//!
//! The tests read manifests and sources as text. That is deliberate: a rule
//! about the shape of the workspace has to see the workspace, and a compile
//! error would arrive too late for the rules about dependency direction.

use std::collections::BTreeMap;
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
        for forbidden in ["fidelity-detect", "fidelity-engine", "fidelity-macros"] {
            assert!(
                !manifest.contains(forbidden),
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
                !manifest.contains("path = \"../../fidelity\""),
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
    for (name, manifest) in crates() {
        for dependency in FORBIDDEN {
            assert!(
                !manifest.contains(&format!("\n{dependency} ")),
                "{name} depends on {dependency}, and ADR-0004 prohibits a remote network client"
            );
        }
    }
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
