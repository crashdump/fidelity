#![no_main]

use fidelity_formats::apk::zip;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = zip::central_directory_offset(data);
});
