//! Measures the cost of one guarded read, so the budget rests on a number.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let key = fidelity_cipher::derive_key(&[7; 16], b"TEAM123456");
    for len in [8_usize, 15, 16, 32, 64, 256] {
        let literal: Vec<u8> = (0..len)
            .map(|index| b'a' + u8::try_from(index % 26).unwrap_or(0))
            .collect();
        let value = fidelity_cipher::encrypt(&key, &literal);
        // The real read copies into a stack array, so the loop must not
        // allocate. A heap allocation here would hide the cipher cost.
        let mut buffer = [0_u8; 256];
        let runs = 200_000;
        let start = Instant::now();
        for _ in 0..runs {
            buffer[..len].copy_from_slice(&value);
            fidelity_cipher::decrypt(black_box(&key), black_box(&mut buffer[..len]));
            black_box(&buffer);
        }
        println!("decrypt {len:>4} bytes: {:>10.1?}", start.elapsed() / runs);
    }
    let runs = 200_000;
    let start = Instant::now();
    for _ in 0..runs {
        black_box(fidelity_cipher::derive_key(black_box(&[7; 16]), b"TEAM"));
    }
    println!("derive_key         : {:>10.1?}", start.elapsed() / runs);
}
