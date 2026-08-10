//! Deterministic test support for Fidelity.
//!
//! This crate is internal, and it makes no promise to a consumer. It never
//! becomes a production extension mechanism, and it never ships as part of the
//! supported surface. A host therefore proves its `ensure_allowed()` placement
//! against a real hostile environment, not against an injected outcome.
//!
//! The crate builds an [`Environment`] whose facts the test states, so a
//! detector test runs on any target and needs no operating-system support.

#![forbid(unsafe_code)]

use std::sync::{Mutex, PoisonError};

use fidelity_core::{
    Baseline, CodeIdentity, CodeOrigin, CodeRegions, Device, Environment, Identity, IdentityMatch,
    Injection, Lifecycle, Observation, SystemBuild, Tracer, TracerState,
};
use fidelity_types::{ExpectedIdentity, Platform};

/// The reason a fact that the test never stated reports.
const NOT_STATED: &str = "this test stated no value for this fact";

/// An environment whose facts the test states.
///
/// Every fact starts at `Unsupported`, so a test states only what it needs. A
/// test that states nothing exercises the default path of every detector.
#[derive(Debug)]
pub struct FakeEnvironment {
    platform: Platform,
    code_identity: Observation<CodeIdentity>,
    identity_match: Observation<IdentityMatch>,
    tracer: Mutex<Script>,
    code_origin: Observation<CodeOrigin>,
    code_regions: Observation<CodeRegions>,
    system_build: Observation<SystemBuild>,
}

/// The answers that one capability gives, in the order a test states them.
///
/// A real environment changes while the worker runs: a debugger attaches to a
/// process that started clean. A fixed answer cannot express that, so the
/// tracer capability reads from a script. The last answer repeats once the
/// script runs out, because a tracer stays attached until it detaches.
///
/// Only the tracer capability takes a script. The others gain one when a test
/// needs a change over time, and not before.
#[derive(Debug)]
struct Script {
    answers: Vec<Observation<TracerState>>,
    next: usize,
}

impl Script {
    /// Returns the answer for this scan, and advances.
    fn answer(&mut self) -> Observation<TracerState> {
        let last = self.answers.len().saturating_sub(1);
        let answer = self
            .answers
            .get(self.next.min(last))
            .cloned()
            .unwrap_or(Observation::Unsupported { reason: NOT_STATED });
        self.next += 1;
        answer
    }
}

impl Default for FakeEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeEnvironment {
    /// Creates an environment that states no fact.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // The tests run on every host, so the platform is a stated value
            // rather than the compilation target.
            platform: Platform::MacOs,
            code_identity: Observation::Unsupported { reason: NOT_STATED },
            identity_match: Observation::Unsupported { reason: NOT_STATED },
            tracer: Mutex::new(Script {
                answers: Vec::new(),
                next: 0,
            }),
            code_origin: Observation::Unsupported { reason: NOT_STATED },
            code_regions: Observation::Unsupported { reason: NOT_STATED },
            system_build: Observation::Unsupported { reason: NOT_STATED },
        }
    }

    /// States the platform that this environment describes.
    #[must_use]
    pub const fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    /// States what the operating system reports about the running image.
    #[must_use]
    pub fn with_code_identity(mut self, observation: Observation<CodeIdentity>) -> Self {
        self.code_identity = observation;
        self
    }

    /// States whether the running image satisfies the expected identity.
    #[must_use]
    pub fn with_identity_match(mut self, observation: Observation<IdentityMatch>) -> Self {
        self.identity_match = observation;
        self
    }

    /// States whether a tracer holds the process.
    ///
    /// Every scan reads the same answer.
    #[must_use]
    pub fn with_tracer_state(self, observation: Observation<TracerState>) -> Self {
        self.with_tracer_sequence(vec![observation])
    }

    /// States one answer for each scan, in order.
    ///
    /// The last answer repeats once the sequence runs out. A test proves that
    /// the worker sees a change with `[Absent, Present]`.
    #[must_use]
    pub fn with_tracer_sequence(self, answers: Vec<Observation<TracerState>>) -> Self {
        *self.tracer.lock().unwrap_or_else(PoisonError::into_inner) = Script { answers, next: 0 };
        self
    }

    /// States what the system reports about its own build.
    #[must_use]
    pub fn with_system_build(mut self, observation: Observation<SystemBuild>) -> Self {
        self.system_build = observation;
        self
    }

    /// States whether a file accounts for every executable region.
    #[must_use]
    pub fn with_code_origin(mut self, observation: Observation<CodeOrigin>) -> Self {
        self.code_origin = observation;
        self
    }

    /// States the executable regions that the process maps.
    #[must_use]
    pub fn with_code_regions(mut self, observation: Observation<CodeRegions>) -> Self {
        self.code_regions = observation;
        self
    }
}

// A stated environment has no thread to prepare, so the default answers.
impl Lifecycle for FakeEnvironment {}

impl Baseline for FakeEnvironment {
    fn code_regions(&self) -> Observation<CodeRegions> {
        self.code_regions.clone()
    }
}

impl Injection for FakeEnvironment {
    fn code_origin(&self) -> Observation<CodeOrigin> {
        self.code_origin.clone()
    }
}

impl Environment for FakeEnvironment {
    fn platform(&self) -> Platform {
        self.platform
    }
}

impl Identity for FakeEnvironment {
    fn code_identity(&self) -> Observation<CodeIdentity> {
        self.code_identity.clone()
    }

    fn identity_match(&self, expected: &ExpectedIdentity) -> Observation<IdentityMatch> {
        let _ = expected;
        self.identity_match.clone()
    }
}

impl Device for FakeEnvironment {
    fn system_build(&self) -> Observation<SystemBuild> {
        self.system_build.clone()
    }
}

impl Tracer for FakeEnvironment {
    fn tracer_state(&self) -> Observation<TracerState> {
        self.tracer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .answer()
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{Environment, Identity, Observation};
    use fidelity_types::Platform;

    use super::FakeEnvironment;

    #[test]
    fn an_unstated_fact_reports_unsupported() {
        assert!(matches!(
            FakeEnvironment::new().code_identity(),
            Observation::Unsupported { .. }
        ));
    }

    #[test]
    fn a_stated_platform_reads_back() {
        let environment = FakeEnvironment::new().with_platform(Platform::Linux);
        assert_eq!(environment.platform(), Platform::Linux);
    }
}
