//! Operating-system access for Android.
//!
//! This crate reports facts. It selects no response, it calculates no score,
//! and it never reports a failed call as a clean result. All `unsafe` code
//! lives under the `sys` boundary module.
//!
//! This crate is an internal implementation detail of Fidelity. It carries no
//! compatibility promise. The `fidelity` crate is the supported surface.
//!
//! # Status
//!
//! Every capability answers. Only
//! `lifecycle` needs the JVM handle that the host supplies: the kernel, the
//! process filesystem, the archive, the loader, and the property store answer
//! the rest, so a shell binary reaches them as well. The coverage matrix in
//! `docs/plan/06-delivery.md` states the row for each one.
//!
//! `dispatch` is the one capability whose rule an application process alone
//! proves, because a shell binary holds this crate in its main image and an
//! application holds it in a library. The instrumented test covers that, and
//! `dispatch_image_path` is what it reads.
//!
//! # Layout
//!
//! One module per capability, named as `fidelity_core::capability` names it.
//! A capability that this platform does not answer gets an empty `impl`, which
//! states the gap without a method body to read.
//!
//! `sys/` reads the operating system, and it interprets nothing. The reader
//! that turns procfs text into values lives in `fidelity-formats`, which Linux
//! calls as well.
//!
//! `sys/` gains the JNI boundary with the first capability that needs Java.
//! The crate defines no `JNI_OnLoad`, because one shared library holds one
//! such function and the host owns it. The host supplies the JVM handle.

#![cfg(target_os = "android")]

mod baseline;
mod device;
mod dispatch;
mod emulation;
mod identity;
mod injection;
mod lifecycle;
mod sys;
mod tracer;

use fidelity_core::Environment;
use fidelity_types::Platform;

/// The Android view of the running process.
///
/// The environment holds the address of the host's virtual machine, because
/// every Java interface needs it and only the host has it. A zero address means
/// the host supplied none, and each capability that needs Java then reports
/// that gap rather than guessing.
#[derive(Debug)]
pub struct AndroidEnvironment {
    java_vm: usize,
}

impl AndroidEnvironment {
    /// Creates the Android environment with no virtual machine.
    ///
    /// The capabilities that the kernel answers still work. Every capability
    /// that needs Java reports that the host supplied no handle.
    #[must_use]
    pub const fn new() -> Self {
        Self { java_vm: 0 }
    }

    /// Creates the Android environment with the host's virtual machine.
    ///
    /// `address` must be the `JavaVM` pointer that JNI gave the host, as a
    /// plain integer. The probe keeps an integer rather than a pointer, so no
    /// caller outside [`sys`](crate::sys) holds one, which is the rule that
    /// `docs/plan/06-delivery.md` states.
    #[must_use]
    pub const fn with_java_vm(address: usize) -> Self {
        Self { java_vm: address }
    }

    /// The address that the host supplied, or zero.
    pub(crate) const fn java_vm(&self) -> usize {
        self.java_vm
    }
}

/// The virtual machine that this process already runs, if the runtime has one.
///
/// The instrumented harness compares this against the handle that JNI gave it,
/// because a call that found a different machine would attach the worker to the
/// wrong one.
#[must_use]
pub fn running_virtual_machine() -> Option<usize> {
    sys::jvm::running()
}

/// The image whose dispatch table the probe reads, as the loader names it.
///
/// The instrumented harness compares this against the library that the
/// application loaded. An application forks from zygote, so its main image is
/// `/system/bin/app_process64`, and a probe that read the table of that binary
/// would watch a system binary rather than the host. Only an application
/// process can prove which image the probe picked, and only this call lets the
/// harness ask.
#[must_use]
pub fn dispatch_image_path() -> Option<String> {
    sys::dispatch::image_path()
}

impl Default for AndroidEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl Environment for AndroidEnvironment {
    fn platform(&self) -> Platform {
        Platform::Android
    }
}
