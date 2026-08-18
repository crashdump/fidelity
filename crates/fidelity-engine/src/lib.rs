//! State, policy, and the worker for the Fidelity runtime.
//!
//! This crate holds the rules that turn a detector outcome into retained
//! state and into an action. It runs no platform code, so every rule here
//! tests on an ordinary machine against a stated environment.
//!
//! The `fidelity` facade is the supported entry point. This crate is an
//! internal implementation detail and carries no compatibility promise.

#![forbid(unsafe_code)]

/// Reports one internal event, and nothing at all without the feature.
///
/// The locked decision index asks for idiomatic `tracing`, and the delivery
/// notes ask that a default build resolve to no external crate. This macro
/// holds both: with the feature off it expands to nothing, so no call site
/// carries a condition of its own and no reader has to find one.
///
/// Two rules apply to a call site. The message states the mechanism only, and
/// never a secret and never host data, because a subscriber that the host
/// selected writes it wherever that host sends its own logs. A binding that
/// only an event reads ends with `drop`, so the code compiles without a warning
/// whichever way the feature stands. A leading underscore reads better and the
/// `used_underscore_binding` lint refuses it.
///
/// This definition sits above every `mod` line below, because that is what puts
/// it in scope for each one. No module imports it.
macro_rules! diagnostic {
    ($($argument:tt)*) => {
        #[cfg(feature = "tracing")]
        ::tracing::debug!($($argument)*);
    };
}

mod policy;
mod state;
mod worker;

pub use policy::Policy;
pub use state::State;
pub use worker::{Callback, Hooks, Worker, now_unix_ms, record};
