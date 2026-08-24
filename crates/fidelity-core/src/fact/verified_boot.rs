//! The facts that the Android Verified Boot capability reports.

use fidelity_types::BoundedText;

/// What Android reports about boot verification and the bootloader lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootVerification {
    /// Android reports a verified system and a locked bootloader.
    Verified,

    /// Android reports an unverified system or an unlocked bootloader.
    Unverified {
        /// Which verified-boot state reports the weakness.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::BootVerification;

    #[test]
    fn an_unverified_boot_keeps_its_detail() {
        let state = BootVerification::Unverified {
            detail: BoundedText::new("Android reports an unlocked bootloader"),
        };
        assert_eq!(
            state,
            BootVerification::Unverified {
                detail: BoundedText::new("Android reports an unlocked bootloader"),
            }
        );
    }
}
