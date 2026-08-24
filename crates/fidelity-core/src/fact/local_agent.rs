//! The fact that the local-agent capability reports.

use fidelity_types::BoundedText;

/// Whether a compatible local instrumentation endpoint answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAgentState {
    /// No compatible endpoint answered.
    Absent,

    /// A compatible endpoint answered on loopback.
    Present {
        /// Which bounded protocol exchange identified the endpoint.
        detail: BoundedText,
    },
}
