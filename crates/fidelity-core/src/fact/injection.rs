//! The facts that the injection capability reports.

use fidelity_types::BoundedText;

/// What the operating system reports about the code in this process.
///
/// The capability asks one question: does this process execute code that no
/// file on disk accounts for? A loader maps code from a file, so code that
/// arrives another way is either a run-time compiler or an injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeOrigin {
    /// Every executable region comes from a file, or from a region that the
    /// kernel named.
    Accounted,

    /// At least one executable region has no file behind it.
    Unaccounted {
        /// How many regions have no file behind them.
        regions: u32,
        /// What the probe found, in text that holds no application data.
        detail: BoundedText,
    },
}

#[cfg(test)]
mod tests {
    use fidelity_types::BoundedText;

    use super::CodeOrigin;

    #[test]
    fn unaccounted_code_keeps_its_count() {
        let origin = CodeOrigin::Unaccounted {
            regions: 2,
            detail: BoundedText::new("two regions have no file behind them"),
        };
        assert!(matches!(origin, CodeOrigin::Unaccounted { regions: 2, .. }));
    }

    #[test]
    fn accounted_code_differs_from_unaccounted_code() {
        assert_ne!(
            CodeOrigin::Accounted,
            CodeOrigin::Unaccounted {
                regions: 1,
                detail: BoundedText::new("one region has no file behind it"),
            }
        );
    }
}
