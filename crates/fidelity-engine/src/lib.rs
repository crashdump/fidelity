//! State, policy, and the worker for the Fidelity runtime.
//!
//! This crate holds the rules that turn a detector outcome into retained
//! state and into an action. It runs no platform code, so every rule here
//! tests on an ordinary machine against a stated environment.
//!
//! The `fidelity` facade is the supported entry point. This crate is an
//! internal implementation detail and carries no compatibility promise.

#![forbid(unsafe_code)]

mod policy;
mod state;
mod worker;

pub use policy::Policy;
pub use state::State;
pub use worker::{Callback, Hooks, Worker, now_unix_ms, record};
