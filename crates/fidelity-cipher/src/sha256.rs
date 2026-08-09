//! SHA-256, as FIPS 180-4 defines it.
//!
//! Fidelity carries its own implementation, because the workspace takes no
//! dependency. The tests check it against the published vectors, so the
//! implementation is verifiable rather than trusted.

/// The round constants of FIPS 180-4, section 4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial state of FIPS 180-4, section 5.3.3.
const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The SHA-256 digest of one message.
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut state = INITIAL;

    let mut chunks = message.chunks_exact(64);
    for chunk in &mut chunks {
        let mut block = [0_u8; 64];
        block.copy_from_slice(chunk);
        compress(&mut state, &block);
    }

    // The padding is one set bit, then zeros, then the length in bits. It
    // needs one extra block when the tail leaves no room for both.
    let tail = chunks.remainder();
    let mut block = [0_u8; 64];
    block[..tail.len()].copy_from_slice(tail);
    block[tail.len()] = 0x80;

    let bits = (message.len() as u64).wrapping_mul(8);
    if tail.len() + 1 + 8 > 64 {
        compress(&mut state, &block);
        block = [0_u8; 64];
    }
    block[56..].copy_from_slice(&bits.to_be_bytes());
    compress(&mut state, &block);

    let mut digest = [0_u8; 32];
    for (slot, word) in digest.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Mixes one 64-byte block into the state.
///
/// The eight working variables keep the single-letter names of FIPS 180-4,
/// section 6.2.2. A reader checks this code against the standard, so matching
/// the standard is clearer than inventing longer names.
#[expect(
    clippy::many_single_char_names,
    reason = "the names come from FIPS 180-4, section 6.2.2"
)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0_u32; 64];
    for (slot, word) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *slot = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for index in 16..64 {
        let a = schedule[index - 15];
        let b = schedule[index - 2];
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let first = h
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(K[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::sha256;

    fn hex(digest: [u8; 32]) -> String {
        digest.iter().fold(String::new(), |mut text, byte| {
            use core::fmt::Write;
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn the_empty_message_matches_the_published_vector() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_one_block_vector_matches() {
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_two_block_vector_matches() {
        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(sha256(message)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn the_long_message_vector_matches() {
        let message = "a".repeat(1_000_000);
        assert_eq!(
            hex(sha256(message.as_bytes())),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn a_message_that_fills_a_block_exactly_pads_into_a_new_one() {
        // 56 bytes leaves no room for the set bit and the length together, so
        // this exercises the second padding block.
        let message = "a".repeat(56);
        assert_eq!(
            hex(sha256(message.as_bytes())),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn a_single_bit_change_changes_the_digest() {
        assert_ne!(sha256(b"abc"), sha256(b"abd"));
    }
}
