#![no_main]

use fidelity_formats::macho::dispatch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((count, commands)) = data.split_first_chunk::<4>() else {
        return;
    };
    let _ = dispatch::dispatch_layout(commands, u32::from_le_bytes(*count));
});
