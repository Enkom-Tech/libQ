//! Cross-backend equivalence: the scalar and hardware AES backends must produce
//! bit-for-bit identical ciphertext and tag for all inputs.
//!
//! When no hardware backend is active on this machine, the dispatch path *is* the
//! scalar path, so the check is trivially satisfied; it becomes meaningful once a
//! build/CPU with AES-NI or ARMv8 AES runs it (and is reported via
//! `hardware_backend_active`).

use lib_q_rocca_s::_internals::{
    dispatch_decrypt,
    dispatch_encrypt,
    hardware_backend_active,
    scalar_decrypt,
    scalar_encrypt,
};

// Small xorshift PRNG for deterministic, dependency-free pseudo-random inputs.
struct Rng(u64);
impl Rng {
    fn next_u8(&mut self) -> u8 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 33) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

#[test]
fn scalar_matches_dispatch() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for len in [0usize, 1, 16, 17, 31, 32, 48, 64, 65, 127, 256, 300, 1000] {
        let key: [u8; 32] = rng.bytes(32).try_into().unwrap();
        let nonce: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let ad = rng.bytes(len % 19);
        let msg = rng.bytes(len);

        let mut ct_scalar = vec![0u8; len];
        let mut ct_dispatch = vec![0u8; len];
        let tag_scalar = scalar_encrypt(&key, &nonce, &ad, &msg, &mut ct_scalar);
        let tag_dispatch = dispatch_encrypt(&key, &nonce, &ad, &msg, &mut ct_dispatch);

        assert_eq!(ct_scalar, ct_dispatch, "ciphertext differs at len {len}");
        assert_eq!(tag_scalar, tag_dispatch, "tag differs at len {len}");

        // Decryption equivalence (and round-trip correctness).
        let mut pt_scalar = vec![0u8; len];
        let mut pt_dispatch = vec![0u8; len];
        let dtag_scalar = scalar_decrypt(&key, &nonce, &ad, &ct_scalar, &mut pt_scalar);
        let dtag_dispatch = dispatch_decrypt(&key, &nonce, &ad, &ct_dispatch, &mut pt_dispatch);
        assert_eq!(pt_scalar, msg, "scalar decrypt round-trip at len {len}");
        assert_eq!(pt_dispatch, msg, "dispatch decrypt round-trip at len {len}");
        assert_eq!(
            dtag_scalar, dtag_dispatch,
            "decrypt tag differs at len {len}"
        );
    }

    // Surface which backend actually ran, for diagnostic clarity.
    eprintln!("hardware AES backend active: {}", hardware_backend_active());
}
