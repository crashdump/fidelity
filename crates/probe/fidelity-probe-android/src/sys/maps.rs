//! The mapping-table boundary.
//!
//! The kernel writes the mapping table as text, so this module reads the file
//! and returns the text. It interprets nothing: `fidelity-formats` does that,
//! and a recorded fixture tests it on any machine.

/// Where the kernel writes the mapping table of the calling process.
const MAPS_PATH: &str = "/proc/self/maps";

/// Reads the mapping table of this process.
///
/// # Errors
///
/// Returns the reason the read failed. Fidelity never reports a failed read as
/// a clean result.
pub(crate) fn read() -> Result<String, &'static str> {
    std::fs::read_to_string(MAPS_PATH).map_err(|_| "the process mapping table did not open")
}
