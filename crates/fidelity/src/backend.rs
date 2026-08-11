//! The platform backend that this build carries.
//!
//! A target with no probe crate reports [`StartError::PlatformUnavailable`].
//! Fidelity never substitutes an empty environment, because a runtime that
//! reports clean results while it examines nothing is worse than a start
//! failure that the host can see.

use fidelity_core::Environment;

use crate::StartError;

/// Constructs the environment for the target platform.
///
/// # Errors
///
/// Returns [`StartError::PlatformUnavailable`] on a target that ships no
/// probe crate.
#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "a target without a probe crate returns the error, so the signature stays uniform"
)]
pub(crate) fn build() -> Result<Box<dyn Environment>, StartError> {
    Ok(Box::new(fidelity_probe_apple::MacEnvironment::new()))
}

/// Constructs the environment for the target platform.
///
/// # Errors
///
/// Returns [`StartError::PlatformUnavailable`] on a target that ships no
/// probe crate.
#[cfg(target_os = "ios")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "a target without a probe crate returns the error, so the signature stays uniform"
)]
pub(crate) fn build() -> Result<Box<dyn Environment>, StartError> {
    Ok(Box::new(fidelity_probe_apple::IosEnvironment::new()))
}

/// Constructs the environment for the target platform.
///
/// # Errors
///
/// Returns [`StartError::PlatformUnavailable`] on a target that ships no
/// probe crate.
#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "a target without a probe crate returns the error, so the signature stays uniform"
)]
pub(crate) fn build() -> Result<Box<dyn Environment>, StartError> {
    Ok(Box::new(fidelity_probe_linux::LinuxEnvironment::new()))
}

/// Constructs the environment for the target platform.
///
/// # Errors
///
/// Returns [`StartError::PlatformUnavailable`] on a target that ships no
/// probe crate.
#[cfg(target_os = "android")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "a target without a probe crate returns the error, so the signature stays uniform"
)]
pub(crate) fn build() -> Result<Box<dyn Environment>, StartError> {
    Ok(Box::new(fidelity_probe_android::AndroidEnvironment::new()))
}

/// Constructs the environment for the target platform.
///
/// # Errors
///
/// Returns [`StartError::PlatformUnavailable`] on a target that ships no
/// probe crate.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
pub(crate) fn build() -> Result<Box<dyn Environment>, StartError> {
    Err(StartError::PlatformUnavailable {
        reason: "this build ships no probe crate for the target platform",
    })
}
