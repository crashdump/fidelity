#![no_main]

use fidelity_formats::macho::signature;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = signature::entitlements(data);
});
