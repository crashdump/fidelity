//! The Apple operating-system boundary.
//!
//! Every `unsafe` block in this crate lives under this module, and each one
//! states the invariant that it depends on. The module exposes safe functions
//! only, so no caller outside it holds a raw pointer.
//!
//! One file per framework. macOS and iOS share these bindings, which is why
//! the two systems share one crate: a split would duplicate every one of them.

pub(crate) mod dispatch;
pub(crate) mod process;
pub(crate) mod qos;
pub(crate) mod regions;

// A device reports its product name, and the simulator reports the host
// architecture. iOS uses that difference for the machine-host capability.
#[cfg(target_os = "ios")]
pub(crate) mod machine;

// The `SecCode` interface is macOS only, so iOS compiles without it.
#[cfg(target_os = "macos")]
pub(crate) mod security;

// macOS asks whether a monitor runs its kernel. iOS reads its machine name
// instead, because the simulator runs on the host kernel.
#[cfg(target_os = "macos")]
pub(crate) mod vmm;

// The image walk answers on both systems, and only iOS needs it: macOS reads
// its identity through `SecCode`, which reports the same team. The walk stays
// iOS only rather than sit unused on macOS, and `tests/platform/controls/entitle.c`
// is where the same mechanism runs on macOS.
#[cfg(target_os = "ios")]
pub(crate) mod image;
