#![no_main]

use fidelity_formats::macho::entitlements;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = entitlements::team_identifier(text.as_bytes());
    }
});
