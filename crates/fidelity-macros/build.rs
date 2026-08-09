//! Declares the build inputs that `guarded!()` reads.
//!
//! Without these two lines Cargo does not know that the expansion depends on
//! the environment. It then reuses the previous expansion, and a rotated seed
//! produces a byte-identical binary that still carries the old key. Nothing
//! reports that failure, so the declaration is load-bearing.

fn main() {
    println!("cargo:rerun-if-env-changed=FIDELITY_BUILD_SEED");
    println!("cargo:rerun-if-env-changed=FIDELITY_CODE_IDENTITY");
}
