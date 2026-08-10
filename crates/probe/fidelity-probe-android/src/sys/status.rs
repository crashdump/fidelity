//! The procfs boundary.
//!
//! Android runs a Linux kernel, so the process status has the same shape and
//! the same field names. The reader that interprets the text is therefore
//! shared: both probes call `fidelity_formats::procfs`.
//!
//! The boundary itself is not shared, and it stays a few lines in each probe
//! crate. A boundary states which operating system it reads, so a shared one
//! would put two systems in one place and undo the platform axis. Android also
//! diverges here later: a sandbox or a `hidepid` mount can hide procfs, and
//! that is an Android answer to give, not a Linux one.

/// Where the kernel writes the status of the calling process.
const STATUS_PATH: &str = "/proc/self/status";

/// Reads the status text of this process.
///
/// # Errors
///
/// Returns the reason the read failed. The application sandbox can hide
/// procfs, and Fidelity never reports a failed read as a clean result.
pub(crate) fn read() -> Result<String, &'static str> {
    std::fs::read_to_string(STATUS_PATH).map_err(|_| "the process status file did not open")
}

#[cfg(test)]
mod tests {
    use super::read;

    #[test]
    fn the_kernel_writes_the_status_of_this_process() {
        // The clean control for the boundary. A failure means the sandbox hid
        // procfs, which is the case that must never read as clean.
        let text = read().unwrap_or_default();
        assert!(text.contains("TracerPid:"));
    }
}
