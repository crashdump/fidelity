//! Detectors for the `Instrumentation` category.
//!
//! The category asks whether a hook, an injection, or a dynamic analysis tool
//! is present. The [plan](../../../../docs/plan/04-detectors-and-platforms.md)
//! excludes a tool name and a port as high-strength evidence, so what is left
//! is structural: where the code in this process came from.

mod code;

pub use code::UNACCOUNTED_CODE;

pub(crate) use code::unaccounted_code;
