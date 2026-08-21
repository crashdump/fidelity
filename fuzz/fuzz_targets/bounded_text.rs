#![no_main]

use fidelity_types::{BoundedText, MAX_EVIDENCE_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data).into_owned();
    let bounded = BoundedText::new(input);
    assert!(bounded.text().len() <= MAX_EVIDENCE_BYTES);
    assert!(bounded.text().is_char_boundary(bounded.text().len()));
});
