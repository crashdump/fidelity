#![no_main]

use fidelity_formats::elf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = elf::dynamic_table(data);
});
