#![no_main]

use fidelity_formats::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe::certificate_table(data);
});
