//! Reads a guarded constant, so a build can be compared against a repackaged
//! copy of itself.
//!
//! ```text
//! FIDELITY_BUILD_SEED=$(uuidgen) FIDELITY_CODE_IDENTITY=apple:YOURTEAMID \
//!     cargo run --release --example guarded
//! ```
//!
//! The value names the kind of material before it states the material. An
//! Android build writes `android:` and the certificate digest instead.
//!
//! Sign the built binary, run it, then re-sign a copy with another identity
//! and run that. The first prints the literal. The second prints something
//! else, and it reports no error while it does.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new().start()?;

    let host = fidelity::guarded!(&handle, "api.example.com");
    let path = fidelity::guarded!(&handle, "/v1/session/open");

    println!("host: {}", &*host);
    println!("path: {}", &*path);
    println!("both: https://{}{}", &*host, &*path);
    Ok(())
}
