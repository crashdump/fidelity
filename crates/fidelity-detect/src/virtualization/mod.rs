//! Detectors for the `Virtualization` category.
//!
//! The category asks one question: does this system run on the hardware, or
//! inside a machine that something else built? An attacker who owns the
//! machine below the system reads every byte the process holds, and stops it
//! at any instruction, and no check inside the process sees that happen.
//!
//! The [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes one
//! mechanism here. The Windows processor flag is not decisive evidence,
//! because it also identifies ordinary VBS, Hyper-V, WSL2, and Windows
//! Sandbox, which a large share of clean Windows machines run.
//!
//! What is left is what the kernel states about the machine below it.

mod machine_host;

pub use machine_host::MACHINE_HOST;

pub(crate) use machine_host::machine_host;
