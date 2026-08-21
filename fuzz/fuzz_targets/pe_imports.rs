#![no_main]

use fidelity_formats::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe::mapped_import_slots(data, 0x1000, 1024);
});
