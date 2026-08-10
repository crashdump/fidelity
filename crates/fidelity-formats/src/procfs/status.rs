//! The reader for the process status file.
//!
//! The kernel writes `/proc/<pid>/status` as one `Name:\tvalue` line for each
//! field. The reader takes the text and returns one field, so a recorded file
//! tests it on any machine.

/// The field that names the tracer.
const TRACER_FIELD: &str = "TracerPid:";

/// What the status text says about a tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracerPid {
    /// The kernel reports no tracer.
    Absent,

    /// The kernel reports the process that traces this one.
    Present(u32),
}

/// Reads the tracer field out of the process status text.
///
/// Returns `None` when the text holds no readable field. The caller turns that
/// into a detector-health finding, because Fidelity never reports a failed
/// read as a clean result.
#[must_use]
pub fn tracer_pid(text: &str) -> Option<TracerPid> {
    // Match the whole field name at the start of a line. `PPid:` and `NSpid:`
    // also end in a form of "pid", so a search for a fragment would read the
    // wrong number.
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(TRACER_FIELD))?
        .trim();

    match value.parse::<u32>() {
        Ok(0) => Some(TracerPid::Absent),
        Ok(pid) => Some(TracerPid::Present(pid)),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{TracerPid, tracer_pid};

    /// A real status file, captured on Debian and ARM64 on 2026-08-09.
    const CLEAN: &str = include_str!("../fixtures/status-clean.txt");

    /// The same file while `gdb` held the process.
    const TRACED: &str = include_str!("../fixtures/status-traced.txt");

    #[test]
    fn a_clean_process_reports_no_tracer() {
        assert_eq!(tracer_pid(CLEAN), Some(TracerPid::Absent));
    }

    #[test]
    fn a_traced_process_reports_the_tracer() {
        assert_eq!(tracer_pid(TRACED), Some(TracerPid::Present(3499)));
    }

    #[test]
    fn the_reader_takes_the_tracer_field_and_not_the_parent_field() {
        // `PPid:` sits directly above `TracerPid:` in the real file, and both
        // end in a form of "pid". A fragment search would read the parent.
        let text = "PPid:\t42\nTracerPid:\t0\n";
        assert_eq!(tracer_pid(text), Some(TracerPid::Absent));
    }

    #[test]
    fn an_absent_field_reads_as_no_answer() {
        assert_eq!(tracer_pid("Name:\tcat\nPPid:\t42\n"), None);
    }

    #[test]
    fn an_unreadable_value_reads_as_no_answer() {
        // Never a clean result. The caller reports detector health instead.
        assert_eq!(tracer_pid("TracerPid:\tnonsense\n"), None);
    }

    #[test]
    fn empty_text_reads_as_no_answer() {
        assert_eq!(tracer_pid(""), None);
    }
}
