//! The injection capability on Windows.
//!
//! A loader maps a module as an image section, so executable memory that no
//! image and no named file backs arrived another way. Windows states the kind
//! of each region directly, so this platform answers the structural question
//! without reading a path, and without the name that the plan excludes.

use fidelity_core::{CodeOrigin, Injection, Observation};
use fidelity_types::BoundedText;

use crate::WindowsEnvironment;
use crate::sys;

impl Injection for WindowsEnvironment {
    fn code_origin(&self) -> Observation<CodeOrigin> {
        let walked = match sys::memory::executable() {
            Ok(walked) => walked,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        let mut regions: u32 = 0;
        let mut bytes: u64 = 0;
        for region in walked.iter().filter(|region| !region.accounted()) {
            regions = regions.saturating_add(1);
            bytes = bytes.saturating_add(region.end.saturating_sub(region.start));
        }

        if regions == 0 {
            return Observation::Fact(CodeOrigin::Accounted);
        }
        Observation::Fact(CodeOrigin::Unaccounted {
            regions,
            detail: BoundedText::new(format!(
                "unaccounted executable memory: {bytes} bytes, region count {regions}"
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{CodeOrigin, Injection, Observation};

    use super::WindowsEnvironment;

    #[test]
    fn a_clean_process_accounts_for_all_of_its_code() {
        // The clean control. The hostile control maps executable memory with
        // no file behind it, in `crates/fidelity/examples/inject.rs`.
        //
        // This test states the measurement that decides whether the rule
        // holds on Windows. A runtime that compiles code allocates private
        // executable memory, in the same way that Node does on Linux, so a
        // failure here is a real result rather than a broken test.
        assert_eq!(
            WindowsEnvironment::new().code_origin(),
            Observation::Fact(CodeOrigin::Accounted)
        );
    }
}
