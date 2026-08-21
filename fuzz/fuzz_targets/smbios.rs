#![no_main]

use fidelity_formats::smbios::system;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = system::system_information(data);
});
