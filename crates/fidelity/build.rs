//! Declares the build input that the guarded-constant key depends on.
//!
//! `guarded!()` expands in the host's own compilation, and it encrypts each
//! literal with the code identity that `FIDELITY_CODE_IDENTITY` names. The
//! runtime has to know that the build made that choice. A build that names an
//! identity, on a platform that reports no signer, decrypts every guarded
//! constant to a wrong value and reports nothing, because a guarded read has
//! no error path by design. `start()` refuses that combination, and this
//! script is how it learns which combination it is in.
//!
//! This script also fails a build whose value belongs to another platform. It
//! is the one place that reads both the value and the target, because Cargo
//! states `CARGO_CFG_TARGET_OS` to a build script and to nothing else. The
//! macro expands in the host crate, where that name is absent, so the macro
//! cannot make this check.
//!
//! `fidelity-macros/build.rs` declares the same variable for the expansion.
//! Both scripts run in one Cargo invocation and read one environment, so the
//! two never disagree.

use fidelity_cipher::binding::{self, Binding};

/// The variable that carries the identity choice of a build.
const IDENTITY: &str = "FIDELITY_CODE_IDENTITY";

/// The variable that Cargo states to a build script, and to nothing else.
const TARGET_OS: &str = "CARGO_CFG_TARGET_OS";

fn main() {
    println!("cargo:rerun-if-env-changed={IDENTITY}");

    let bound = binds_identity(
        &std::env::var(IDENTITY).unwrap_or_default(),
        &std::env::var(TARGET_OS).unwrap_or_default(),
    );
    println!("cargo:rustc-env=FIDELITY_BINDS_IDENTITY={bound}");
}

/// Reports whether this build binds guarded constants to a code identity.
///
/// # Panics
///
/// Panics when the value is unusable, or when it belongs to another platform.
/// A build script has no other way to stop a build, and a wrong value here
/// makes every guarded constant read wrong with nothing to report it.
fn binds_identity(stated: &str, target_os: &str) -> bool {
    // Silence is not a choice, and the macro already fails a build that states
    // nothing. A crate that holds no guarded constant never expands the macro,
    // so silence has to stay allowed here, and it binds to nothing.
    if stated.is_empty() {
        return false;
    }

    match binding::parse(stated) {
        Ok(Binding::Absent) => false,
        Ok(Binding::Present { material, .. }) => {
            if let Err(reason) = binding::check_target(material, target_os) {
                panic!("{IDENTITY} names the wrong platform: {reason}");
            }
            true
        }
        Err(reason) => panic!("{IDENTITY} states no usable value: {reason}"),
    }
}
