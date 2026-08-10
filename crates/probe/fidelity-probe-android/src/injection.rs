//! The injection capability on Android.

use fidelity_core::{CodeOrigin, Injection, Observation};
use fidelity_formats::procfs::maps;
use fidelity_types::BoundedText;

use crate::AndroidEnvironment;
use crate::sys;

impl Injection for AndroidEnvironment {
    fn code_origin(&self) -> Observation<CodeOrigin> {
        let text = match sys::maps::read() {
            Ok(text) => text,
            Err(detail) => {
                return Observation::Failed {
                    detail: BoundedText::new(detail),
                };
            }
        };

        let found = maps::unaccounted(&text);
        if found.is_empty() {
            return Observation::Fact(CodeOrigin::Accounted);
        }
        Observation::Fact(CodeOrigin::Unaccounted {
            regions: found.regions,
            detail: BoundedText::new(format!(
                "unaccounted executable memory: {} bytes, region count {}",
                found.bytes, found.regions
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use fidelity_core::{CodeOrigin, Injection, Observation};

    use super::AndroidEnvironment;

    #[test]
    fn a_clean_process_accounts_for_all_of_its_code() {
        // The clean control. The hostile control maps executable memory with
        // no file behind it, in `crates/fidelity/examples/inject.rs`.
        assert_eq!(
            AndroidEnvironment::new().code_origin(),
            Observation::Fact(CodeOrigin::Accounted)
        );
    }
}
