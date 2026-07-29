//! Differential test: the AVX2 keystream must equal the portable keystream, byte for byte.
//!
//! `crypto::xor_body` chooses between `simd::avx2::xor_keystream_avx2` and
//! `Portable::xor_keystream` at runtime. Byte-for-byte equality of the two IS the AVX2 path's
//! entire correctness contract, and before this file nothing in the workspace tested it.
//!
//! `tests/roundtrip.rs` structurally cannot: every one of its tests encrypts and then decrypts
//! through the *same* `xor_body` branch, so CTR self-inverse cancels any keystream error and the
//! roundtrip still passes on a completely wrong keystream. (Verified: injecting a counter fault
//! into the batched loop left all 8 roundtrip tests green.)
//!
//! Lengths >= `4 * BLOCK_BYTES` (128) are the ones that carry the signal — only they enter the
//! AVX2 4-way batched loop. Shorter inputs fall through to the same scalar `keystream_block`
//! tail the portable implementation uses, so they can never disagree.
//!
//! All data is generated from FIXED seeds (no clock, no system entropy) so any failure
//! reproduces exactly from the printed set index and length.
#![cfg(all(feature = "simd-avx2", target_arch = "x86_64"))]

use lib_q_tweak_aead::block::keystream_block;
use lib_q_tweak_aead::params::{
    BLOCK_BYTES,
    KEY_BYTES,
    NONCE_BYTES,
};
use lib_q_tweak_aead::simd::avx2::xor_keystream_avx2;
use lib_q_tweak_aead::simd::runtime::has_avx2;
use lib_q_tweak_aead::simd::{
    Portable,
    TweakAeadStreamOps,
};

/// Every length at which `xor_keystream_avx2` changes which of its three loops runs: empty,
/// sub-block, exact block multiples, block +/- 1, the 4-block batch boundary (128) and its
/// neighbours, several whole batches, and a long buffer (4096 = 32 batches).
const LENGTHS: &[usize] = &[
    0, 1, 2, 15, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 130, 159, 160, 161, 255, 256,
    257, 384, 1000, 4096,
];

/// Deterministic filler (fixed seed in, same bytes out — never clock- or entropy-seeded).
fn fill_deterministic(seed: u64, out: &mut [u8]) {
    let mut x = seed;
    for b in out {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (x >> 56) as u8;
    }
}

/// (key, nonce) pairs: both degenerate ends (all-zero, all-0xFF) plus six pseudorandom sets.
fn key_nonce_sets() -> Vec<([u8; KEY_BYTES], [u8; NONCE_BYTES])> {
    let mut sets = vec![
        ([0x00u8; KEY_BYTES], [0x00u8; NONCE_BYTES]),
        ([0xFFu8; KEY_BYTES], [0xFFu8; NONCE_BYTES]),
    ];
    for i in 0..6u64 {
        let mut key = [0u8; KEY_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        fill_deterministic(0x1000 + i, &mut key);
        fill_deterministic(0x2000 + i, &mut nonce);
        sets.push((key, nonce));
    }
    sets
}

/// Third reference, written straight from the CTR definition (block index = byte offset /
/// `BLOCK_BYTES`) and sharing no loop structure with either implementation under test.
fn naive_xor_keystream(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], pt: &[u8], ct: &mut [u8]) {
    for (b, chunk) in pt.chunks(BLOCK_BYTES).enumerate() {
        let ks = keystream_block(key, nonce, b as u64);
        for (j, &p) in chunk.iter().enumerate() {
            ct[b * BLOCK_BYTES + j] = p ^ ks[j];
        }
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

#[test]
fn avx2_keystream_matches_portable_over_lengths_and_keys() {
    // SAFETY GATE: `xor_keystream_avx2` is `#[target_feature(enable = "avx2")]`; calling it on a
    // CPU without AVX2 is undefined behaviour. Same idiom as
    // `lib-q-saturnin/tests/simd_equivalence.rs` and `lib-q-hqc/tests/vect_mul_equivalence.rs`.
    if !has_avx2() {
        return;
    }

    let mut batched_vectors = 0usize;
    for (set_idx, (key, nonce)) in key_nonce_sets().iter().enumerate() {
        for &len in LENGTHS {
            let mut pt = vec![0u8; len];
            fill_deterministic(0x3000 + (set_idx as u64) * 8192 + len as u64, &mut pt);

            let mut avx2_out = vec![0u8; len];
            // SAFETY: guarded by the `has_avx2()` check above; `pt` and `avx2_out` are equal length.
            unsafe {
                xor_keystream_avx2(key, nonce, &pt, &mut avx2_out);
            }

            let mut portable_out = vec![0u8; len];
            <Portable as TweakAeadStreamOps>::xor_keystream(key, nonce, &pt, &mut portable_out);

            let mut naive_out = vec![0u8; len];
            naive_xor_keystream(key, nonce, &pt, &mut naive_out);

            assert_eq!(
                avx2_out,
                portable_out,
                "AVX2 != portable (key/nonce set {}, len {}, first differing byte {:?})",
                set_idx,
                len,
                first_diff(&avx2_out, &portable_out)
            );
            assert_eq!(
                portable_out,
                naive_out,
                "portable != naive CTR reference (key/nonce set {}, len {}, first differing byte \
                 {:?})",
                set_idx,
                len,
                first_diff(&portable_out, &naive_out)
            );

            if len >= 4 * BLOCK_BYTES {
                batched_vectors += 1;
            }
        }
    }

    // Guard against a future edit trimming `LENGTHS` back below the batch boundary, which would
    // leave this test green while testing nothing that the scalar tail does not already cover.
    assert!(
        batched_vectors >= 32,
        "vector table no longer exercises the AVX2 4-way batched loop: only {} vectors are >= {} \
         bytes",
        batched_vectors,
        4 * BLOCK_BYTES
    );
}

#[test]
fn avx2_keystream_is_not_degenerate() {
    // SAFETY GATE: see `avx2_keystream_matches_portable_over_lengths_and_keys`.
    if !has_avx2() {
        return;
    }

    let key = [0x5Au8; KEY_BYTES];
    let nonce = [0xA5u8; NONCE_BYTES];
    // 8 blocks = two full 4-way batches, so the counter also has to advance ACROSS a batch.
    let zeros = vec![0u8; 8 * BLOCK_BYTES];

    let mut ks = vec![0u8; zeros.len()];
    // SAFETY: guarded by the `has_avx2()` check above; buffers are equal length.
    unsafe {
        xor_keystream_avx2(&key, &nonce, &zeros, &mut ks);
    }

    assert!(
        ks.iter().any(|&b| b != 0),
        "keystream is all-zero: XOR would be the identity and every equivalence assertion above \
         would pass vacuously"
    );
    for b in 1..8 {
        assert_ne!(
            ks[(b - 1) * BLOCK_BYTES..b * BLOCK_BYTES],
            ks[b * BLOCK_BYTES..(b + 1) * BLOCK_BYTES],
            "block {} equals block {}: the block counter is not advancing",
            b,
            b - 1
        );
    }

    let mut nonce2 = nonce;
    nonce2[0] ^= 1;
    let mut ks_other_nonce = vec![0u8; zeros.len()];
    // SAFETY: guarded by the `has_avx2()` check above; buffers are equal length.
    unsafe {
        xor_keystream_avx2(&key, &nonce2, &zeros, &mut ks_other_nonce);
    }
    assert_ne!(ks, ks_other_nonce, "keystream does not depend on the nonce");

    let mut key2 = key;
    key2[0] ^= 1;
    let mut ks_other_key = vec![0u8; zeros.len()];
    // SAFETY: guarded by the `has_avx2()` check above; buffers are equal length.
    unsafe {
        xor_keystream_avx2(&key2, &nonce, &zeros, &mut ks_other_key);
    }
    assert_ne!(ks, ks_other_key, "keystream does not depend on the key");
}
