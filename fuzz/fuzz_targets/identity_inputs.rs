#![no_main]

use fidelity_types::{
    AuthenticodeThumbprint, CertificateSha256, CodeRequirement, ContentDigest, TeamIdentifier,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    let _ = AuthenticodeThumbprint::from_hex(&text);
    let _ = CertificateSha256::from_hex(&text);
    let _ = CodeRequirement::new(text.clone());
    let _ = TeamIdentifier::new(text);
    let _ = ContentDigest::new(data.to_vec());
});
