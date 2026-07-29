//! Dev-only: print hex for the KATs in `src/crypto.rs`
//! (`cargo run -p lib-q-tweak-aead --example dump_tweak_kat`).
//!
//! Run this WITHOUT `--features simd-avx2` when regenerating: the expected bytes must come from
//! the portable path so that the KAT is an independent oracle for the AVX2 path, not a recording
//! of it.
use lib_q_tweak_aead::params::{
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Inputs for `kat_encrypt_multi_block_293`, kept in one place so the test and this generator
/// cannot drift apart. See that test for why 293 bytes.
fn multi_block_inputs() -> ([u8; KEY_BYTES], [u8; NONCE_BYTES], &'static [u8], Vec<u8>) {
    let mut key = [0u8; KEY_BYTES];
    for (i, k) in key.iter_mut().enumerate() {
        *k = i as u8;
    }
    // Fixed by construction: this example regenerates the KAT expected bytes, so its inputs must
    // match `kat_encrypt_multi_block_293` exactly. Never used to encrypt real data.
    // codeql[rust/hard-coded-cryptographic-value]
    let mut nonce = [0u8; NONCE_BYTES];
    for (i, n) in nonce.iter_mut().enumerate() {
        *n = 0x10 + i as u8;
    }
    let pt: Vec<u8> = (0..293).map(|i| i as u8).collect();
    (key, nonce, b"lib-q tweak-aead KAT", pt)
}

fn main() {
    // Same fixed inputs as the pre-existing `kat_encrypt_libq_empty_ad` vector, for the same
    // reason: this regenerates that KAT, it does not encrypt anything real.
    let key = [0u8; KEY_BYTES];
    // codeql[rust/hard-coded-cryptographic-value]
    let nonce = [0u8; NONCE_BYTES];
    let mut out = [0u8; 4 + TAG_BYTES];
    lib_q_tweak_aead::crypto::encrypt(&key, &nonce, b"", b"libQ", &mut out).unwrap();
    println!("kat_encrypt_libq_empty_ad     = {}", to_hex(&out));

    let (key, nonce, ad, pt) = multi_block_inputs();
    let mut out = vec![0u8; pt.len() + TAG_BYTES];
    lib_q_tweak_aead::crypto::encrypt(&key, &nonce, ad, &pt, &mut out).unwrap();
    println!("kat_encrypt_multi_block_293   = {}", to_hex(&out));
}
