/// The response that the host selects for one category.
///
/// Actions do not compose. Each category carries exactly one action, and the
/// project ships no presets and no policy language. A host that needs a
/// custom or multi-step response selects [`Action::Callback`].
///
/// The enumeration stays exhaustive, so a host match needs no wildcard arm.
///
/// # Examples
///
/// ```
/// use fidelity_types::Action;
///
/// // Every category starts at `Report`.
/// assert_eq!(Action::default(), Action::Report);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Action {
    /// Publish the finding and keep running.
    ///
    /// This is the default for every category. The host reads the finding
    /// from the snapshot, because no callback runs for this action.
    #[default]
    Report,

    /// Latch a process-wide denial that the host checks.
    ///
    /// The latch is permanent and cooperative. It denies nothing on its own,
    /// so the host must place its check at every protected operation.
    Deny,

    /// Invoke the host callback after the runtime latches the state.
    Callback,

    /// Stop the current process at once, without an unwind or cleanup.
    ///
    /// The finding is authoritative state before the process stops, but the
    /// callback may never run.
    Crash,
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn default_action_is_report() {
        assert_eq!(Action::default(), Action::Report);
    }

    #[test]
    fn actions_compare_by_identity() {
        assert_ne!(Action::Deny, Action::Crash);
    }
}
