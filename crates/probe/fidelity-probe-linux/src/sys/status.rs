//! The procfs boundary.
//!
//! The kernel writes the process status as text, so this module reads the file
//! and returns the text. It interprets nothing: `fidelity-formats` does that,
//! and a recorded fixture tests it on any machine.

/// Where the kernel writes the status of the calling process.
const STATUS_PATH: &str = "/proc/self/status";

/// Reads the status text of this process.
///
/// # Errors
///
/// Returns the reason the read failed. A container or a sandbox can hide
/// procfs, and Fidelity never reports a failed read as a clean result.
pub(crate) fn read() -> Result<String, &'static str> {
    std::fs::read_to_string(STATUS_PATH).map_err(|_| "the process status file did not open")
}

#[cfg(test)]
mod tests {
    use super::read;

    #[test]
    fn the_kernel_writes_the_status_of_this_process() {
        // The clean control for the boundary. A failure means procfs is
        // absent, which is the case that must never read as clean.
        let text = read().unwrap_or_default();
        assert!(text.contains("TracerPid:"));
    }
}
