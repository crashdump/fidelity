//! Detectors for the `Instrumentation` category.
//!
//! The category asks whether a hook, an injection, or a dynamic analysis tool
//! is present. The [plan](../../../../docs/plan/04-detectors-and-platforms.md)
//! excludes a tool name and a port as high-strength evidence, so what is left
//! is structural. Two detectors answer it: `unaccounted_code` asks where the
//! code in this process came from, and `dispatch_targets` asks whether a call
//! of the main image now reaches a different address than at start.

mod code;
mod dispatch;
mod image_catalog;
mod local_agent;

pub use code::UNACCOUNTED_CODE;
pub use dispatch::DISPATCH_TARGETS;
pub use image_catalog::IMAGE_CATALOG;
pub use local_agent::LOCAL_AGENT;

pub(crate) use code::unaccounted_code;
pub(crate) use dispatch::dispatch_targets;
pub(crate) use image_catalog::image_catalog;
pub(crate) use local_agent::local_agent;
