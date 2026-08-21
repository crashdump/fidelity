#![no_main]

use fidelity_formats::macho::image;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((header, commands)) = data.split_first_chunk::<12>() else {
        return;
    };
    let count = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let slide = i64::from_le_bytes([
        header[4], header[5], header[6], header[7], header[8], header[9], header[10], header[11],
    ]);
    let _ = image::signature_layout(commands, count, slide);
});
