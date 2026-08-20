//! Capability code that both Apple systems run.
//!
//! macOS and iOS ask the kernel the same two questions, through the same two
//! interfaces, so each body lives here once.
//!
//! Each system still keeps an `impl` in a file of the capability name. The
//! platform axis stays readable only while a reader can list one file name
//! across the probe crates, so a shared body must not remove that file. See
//! `docs/plan/06-delivery.md`.

pub(crate) mod baseline;
pub(crate) mod dispatch;
pub(crate) mod lifecycle;
pub(crate) mod tracer;
