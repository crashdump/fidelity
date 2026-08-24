use fidelity_types::Platform;

use crate::capability::{
    Baseline, Device, Dispatch, Emulation, Identity, ImageCatalog, Injection, Lifecycle,
    LocalAgent, Tracer, VerifiedBoot,
};

/// Everything that one platform reports.
///
/// The trait inherits every capability, so the engine holds one value and each
/// probe crate offers one type. A detector takes the capability it reads, not
/// this trait, so its signature states what it touches.
///
/// A probe implements the capabilities that its platform offers, and writes an
/// empty `impl` for the rest. The empty `impl` states the gap.
pub trait Environment:
    Baseline
    + Device
    + Dispatch
    + Emulation
    + Identity
    + ImageCatalog
    + Injection
    + Lifecycle
    + LocalAgent
    + Tracer
    + VerifiedBoot
    + Send
    + Sync
    + 'static
{
    /// The platform that this environment describes.
    fn platform(&self) -> Platform;
}

#[cfg(test)]
mod tests {
    use fidelity_types::{ExpectedIdentity, Platform};

    use super::Environment;
    use crate::Observation;
    use crate::capability::{
        Baseline, Device, Dispatch, Emulation, Identity, ImageCatalog, Injection, Lifecycle,
        LocalAgent, Tracer, VerifiedBoot,
    };

    /// A probe that offers no capability, so every default answers.
    #[derive(Debug)]
    struct Bare;

    impl Identity for Bare {}

    impl Tracer for Bare {}

    impl Injection for Bare {}

    impl ImageCatalog for Bare {}

    impl Baseline for Bare {}

    impl Dispatch for Bare {}

    impl Device for Bare {}

    impl VerifiedBoot for Bare {}

    impl Emulation for Bare {}

    impl Lifecycle for Bare {}

    impl LocalAgent for Bare {
        fn local_agent_state(&self) -> Observation<crate::LocalAgentState> {
            Observation::Unsupported {
                reason: "no test fact",
            }
        }
    }

    impl Environment for Bare {
        fn platform(&self) -> Platform {
            Platform::Linux
        }
    }

    /// A detector takes the capability it reads, not the whole environment.
    ///
    /// The `?Sized` bound is what lets `&dyn Environment` pass, so every
    /// detector carries it.
    fn reads_identity(probe: &(impl Identity + ?Sized)) -> bool {
        matches!(probe.code_identity(), Observation::Unsupported { .. })
    }

    #[test]
    fn a_bare_probe_reports_its_platform() {
        assert_eq!(Bare.platform(), Platform::Linux);
    }

    #[test]
    fn an_absent_capability_defaults_to_unsupported() {
        assert!(reads_identity(&Bare));
    }

    #[test]
    fn an_absent_match_defaults_to_unsupported() {
        assert!(matches!(
            Bare.identity_match(&ExpectedIdentity::new()),
            Observation::Unsupported { .. }
        ));
    }

    #[test]
    fn an_environment_passes_where_a_capability_is_wanted() {
        // The engine holds `&dyn Environment`, and a detector wants the narrow
        // trait. The supertrait makes that work without an upcast.
        let environment: &dyn Environment = &Bare;
        assert!(reads_identity(environment));
    }
}
