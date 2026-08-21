#![no_main]

use fidelity_formats::elf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = elf::jump_slots(data, 7, 4097);
    let _ = elf::jump_slots(data, 1026, 4097);
});
