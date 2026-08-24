//! Android Verified Boot state.
//!
//! Android states the boot result and the bootloader lock in its property
//! store. The detector reads both because either one alone gives an incomplete
//! answer. `ro.boot.flash.locked` is the compatibility fallback for systems
//! that do not state `ro.boot.vbmeta.device_state`.

use core::ffi::CStr;

use fidelity_core::{BootVerification, Observation, VerifiedBoot};
use fidelity_types::BoundedText;

use super::AndroidEnvironment;
use crate::sys::property;

/// The property that states the Android Verified Boot result.
const VERIFIED_BOOT_STATE: &CStr = c"ro.boot.verifiedbootstate";

/// The property that states the vbmeta device lock.
const VBMETA_DEVICE_STATE: &CStr = c"ro.boot.vbmeta.device_state";

/// The compatibility property that states the bootloader lock.
const FLASH_LOCKED: &CStr = c"ro.boot.flash.locked";

/// The property store did not state the boot result.
const NO_BOOT_STATE: &str = "the property store did not state ro.boot.verifiedbootstate";

/// The property store did not state a bootloader lock.
const NO_LOCK_STATE: &str = "the property store did not state a bootloader lock";

/// The property store stated an unknown verified-boot value.
const UNKNOWN_BOOT_STATE: &str = "the property store stated an unknown verified-boot value";

/// The property store stated an unknown bootloader lock value.
const UNKNOWN_LOCK_STATE: &str = "the property store stated an unknown bootloader lock value";

/// The two bootloader lock properties disagree.
const LOCK_SOURCES_CONFLICT: &str = "the two bootloader lock properties disagree";

/// The boot result and the bootloader lock disagree.
const BOOT_AND_LOCK_CONFLICT: &str = "the boot result and the bootloader lock disagree";

/// What the yellow verified-boot state reports.
const YELLOW_BOOT: &str =
    "Android reports verifiedbootstate=yellow, so another root of trust signed the system";

/// What the orange verified-boot state reports.
const ORANGE_BOOT: &str = "Android reports verifiedbootstate=orange and an unlocked bootloader";

/// What the red verified-boot state reports.
const RED_BOOT: &str = "Android reports verifiedbootstate=red, so boot verification failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootState {
    Green,
    Yellow,
    Orange,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockState {
    Locked,
    Unlocked,
}

impl VerifiedBoot for AndroidEnvironment {
    fn boot_verification(&self) -> Observation<BootVerification> {
        match judge(
            property::read(VERIFIED_BOOT_STATE).as_deref(),
            property::read(VBMETA_DEVICE_STATE).as_deref(),
            property::read(FLASH_LOCKED).as_deref(),
        ) {
            Ok(state) => Observation::Fact(state),
            Err(reason) => Observation::failed(reason),
        }
    }
}

/// Decides what the verified-boot properties state.
fn judge(
    boot: Option<&str>,
    vbmeta_lock: Option<&str>,
    flash_lock: Option<&str>,
) -> Result<BootVerification, &'static str> {
    let boot = parse_boot(boot)?;
    let lock = lock_state(vbmeta_lock, flash_lock)?;

    match (boot, lock) {
        (BootState::Green, LockState::Locked) => Ok(BootVerification::Verified),
        (BootState::Orange, LockState::Unlocked) => Ok(unverified(ORANGE_BOOT)),
        (BootState::Yellow, _) => Ok(unverified(YELLOW_BOOT)),
        (BootState::Red, _) => Ok(unverified(RED_BOOT)),
        (BootState::Green, LockState::Unlocked) | (BootState::Orange, LockState::Locked) => {
            Err(BOOT_AND_LOCK_CONFLICT)
        }
    }
}

/// Parses the Android Verified Boot color.
fn parse_boot(value: Option<&str>) -> Result<BootState, &'static str> {
    match value {
        Some("green") => Ok(BootState::Green),
        Some("yellow") => Ok(BootState::Yellow),
        Some("orange") => Ok(BootState::Orange),
        Some("red") => Ok(BootState::Red),
        Some(_) => Err(UNKNOWN_BOOT_STATE),
        None => Err(NO_BOOT_STATE),
    }
}

/// Reads the primary lock state and checks the compatibility value.
fn lock_state(vbmeta: Option<&str>, flash: Option<&str>) -> Result<LockState, &'static str> {
    let primary = parse_lock(vbmeta, "locked", "unlocked")?;
    let compatibility = parse_lock(flash, "1", "0")?;

    match (primary, compatibility) {
        (Some(left), Some(right)) if left != right => Err(LOCK_SOURCES_CONFLICT),
        (Some(state), _) | (None, Some(state)) => Ok(state),
        (None, None) => Err(NO_LOCK_STATE),
    }
}

/// Parses one optional bootloader lock value.
fn parse_lock(
    value: Option<&str>,
    locked: &str,
    unlocked: &str,
) -> Result<Option<LockState>, &'static str> {
    match value {
        Some(value) if value == locked => Ok(Some(LockState::Locked)),
        Some(value) if value == unlocked => Ok(Some(LockState::Unlocked)),
        Some(_) => Err(UNKNOWN_LOCK_STATE),
        None => Ok(None),
    }
}

/// Builds an unverified fact with bounded detail.
fn unverified(detail: &'static str) -> BootVerification {
    BootVerification::Unverified {
        detail: BoundedText::new(detail),
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{BootVerification, Observation, VerifiedBoot};

    use super::{AndroidEnvironment, judge};

    #[test]
    fn the_probe_reads_verified_boot_on_this_system() {
        let observation = AndroidEnvironment::new().boot_verification();
        assert!(
            matches!(
                observation,
                Observation::Fact(_) | Observation::Failed { .. }
            ),
            "{observation:?}"
        );
    }

    #[test]
    fn a_green_boot_on_a_locked_device_reports_verified() {
        assert_eq!(
            judge(Some("green"), Some("locked"), Some("1")),
            Ok(BootVerification::Verified)
        );
    }

    #[test]
    fn the_flash_lock_supplies_the_compatibility_fallback() {
        assert_eq!(
            judge(Some("green"), None, Some("1")),
            Ok(BootVerification::Verified)
        );
    }

    #[test]
    fn an_orange_boot_on_an_unlocked_device_reports_unverified() {
        assert!(matches!(
            judge(Some("orange"), Some("unlocked"), Some("0")),
            Ok(BootVerification::Unverified { .. })
        ));
    }

    #[test]
    fn a_yellow_boot_reports_unverified() {
        assert!(matches!(
            judge(Some("yellow"), Some("locked"), Some("1")),
            Ok(BootVerification::Unverified { .. })
        ));
    }

    #[test]
    fn a_red_boot_reports_unverified() {
        assert!(matches!(
            judge(Some("red"), Some("locked"), Some("1")),
            Ok(BootVerification::Unverified { .. })
        ));
    }

    #[test]
    fn an_unlocked_green_boot_reports_a_conflict() {
        assert!(judge(Some("green"), Some("unlocked"), Some("0")).is_err());
    }

    #[test]
    fn two_lock_properties_that_disagree_report_a_conflict() {
        assert!(judge(Some("green"), Some("locked"), Some("0")).is_err());
    }

    #[test]
    fn an_absent_boot_state_reports_a_failed_read() {
        assert!(judge(None, Some("locked"), Some("1")).is_err());
    }

    #[test]
    fn an_absent_lock_state_reports_a_failed_read() {
        assert!(judge(Some("green"), None, None).is_err());
    }

    #[test]
    fn an_unknown_boot_state_reports_a_failed_read() {
        assert!(judge(Some("blue"), Some("locked"), Some("1")).is_err());
    }
}
