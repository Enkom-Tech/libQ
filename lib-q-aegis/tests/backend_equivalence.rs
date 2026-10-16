//! Cross-backend equivalence: the dispatched backend (AES-NI or ARMv8 AES when the
//! CPU has it) and the portable bitsliced backend must agree byte for byte on
//! every length, including every partial-block and HiAE batch boundary.
//!
//! On a CPU without AES support both paths are the portable one and this test is
//! trivially true; `hardware_aes_available()` is printed so CI logs show which.

#![allow(unused_imports)]

use lib_q_aegis::{
    _internals,
    hardware_aes_available,
};

/// Deterministic xorshift byte stream (test data only).
fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn aegis256_dispatch_matches_portable() {
    println!("hardware_aes_available = {}", hardware_aes_available());
    let key: [u8; 32] = stream(1, 32).try_into().unwrap();
    let nonce: [u8; 32] = stream(2, 32).try_into().unwrap();
    for len in (0..=600).chain([1023, 1024, 1025, 1500, 9000]) {
        let ad = stream(3 + len as u64, len % 53);
        let msg = stream(4 + len as u64, len);

        let mut a = msg.clone();
        let mut b = msg.clone();
        let ta: [u8; 32] = _internals::aegis256_seal_dispatch(&key, &nonce, &ad, &mut a);
        let tb: [u8; 32] = _internals::aegis256_seal_soft(&key, &nonce, &ad, &mut b);
        assert_eq!(a, b, "ciphertext len {len}");
        assert_eq!(ta, tb, "tag len {len}");

        let ea: [u8; 32] = _internals::aegis256_open_dispatch(&key, &nonce, &ad, &mut a);
        let eb: [u8; 32] = _internals::aegis256_open_soft(&key, &nonce, &ad, &mut b);
        assert_eq!(a, msg, "plaintext len {len}");
        assert_eq!(b, msg, "plaintext len {len}");
        assert_eq!(ea, ta);
        assert_eq!(eb, ta);
    }
}
