#![no_main]

use fidelity_formats::apk::signing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = signing::block_length(data);
    let _ = signing::signer_certificate(data);
});
