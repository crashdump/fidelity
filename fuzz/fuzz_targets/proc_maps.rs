#![no_main]

use fidelity_formats::procfs::maps;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = maps::executable_mappings(text);
        let _ = maps::package_archive(text, "com.example.app");
        let _ = maps::package_archive_for_image(
            text,
            "/data/app/~~a/com.example.app-b/lib/arm64/libhost.so",
        );
        let _ = maps::unaccounted(text);
        let _ = maps::executable_ranges(text);
        let _ = maps::outside_loader(text, &[(0x1000, 0x2000), (0x4000, 0x8000)]);
    }
});
