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
//! Two properties are pinned here that a differential test does NOT get for free, and that this
//! file did not have when it was first written:
//!
//! 1. **The counter is driven past block index 255** (`DEEP_COUNTER_BYTES`). A table that stops
//!    at 4096 bytes only ever reaches index 127, so any narrowing of the block counter below
//!    64 bits is invisible.
//! 2. **Output buffers start dirty.** With a zeroed `ct`, assignment and XOR-accumulation are
//!    indistinguishable, because 0 is the XOR identity.
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

/// Number of blocks the 4-way BATCHED loop handles for a buffer of `len` bytes.
///
/// `xor_keystream_avx2` runs `while block_idx + 4 <= full_blocks`, so the batched loop covers
/// blocks `0..batched_blocks(len)` and everything above that is handed to the scalar tail
/// (which calls the same `keystream_block` the portable path does). Getting this distinction
/// right is what `DEEP_COUNTER_BYTES` turns on: a length can drive the *counter* past 255 while
/// the *batched loop* never sees an index above 255.
fn batched_blocks(len: usize) -> usize {
    (len / BLOCK_BYTES) / 4 * 4
}

/// Smallest interesting length whose 4-way BATCHED loop is entered with `block_idx` = 256, i.e.
/// the only place a block counter narrowed below 64 bits can be caught.
///
/// 8357 = 261 full blocks + 5. `batched_blocks(8357)` = 260, so the final batch covers blocks
/// 256..259 — inside the batched loop — then the scalar tail takes block 260 and the remainder
/// takes 261.
///
/// The arithmetic matters, and the obvious value is wrong. 8256 bytes (258 blocks) *does* drive
/// the counter to 257, but `batched_blocks(8256)` = 256: indices 256 and 257 are handled by the
/// scalar tail, not the batched loop. Truncating `block_idx + i as u64` to `u8` at
/// `src/simd/avx2.rs:44` is therefore still invisible at 8256 — verified, the whole suite stayed
/// green. The batched loop needs `full_blocks >= 260` before it touches index 256 at all.
///
/// This is not decoration. The table used to top out at 4096 = 128 blocks, so *any* defect that
/// first shows above block index 127 was invisible — including the whole class of "the counter
/// is materialised in something narrower than u64", which is what a vectorised-counter rewrite
/// (broadcasting four lanes of `block_idx` into a `__m256i` instead of calling the scalar
/// `setup_state_pre_f1600` four times) would introduce.
const DEEP_COUNTER_BYTES: usize = 8357;

/// The boundary itself: `batched_blocks(8192)` = 256, so the batched loop's highest index is
/// exactly 255. Pairs with `DEEP_COUNTER_BYTES` to separate an off-by-one at the boundary from a
/// wholesale wrap past it.
const BOUNDARY_COUNTER_BYTES: usize = 8192;

/// Every length at which `xor_keystream_avx2` changes which of its three loops runs: empty,
/// sub-block, exact block multiples, block +/- 1, the 4-block batch boundary (128) and its
/// neighbours, several whole batches, a long buffer (4096 = 32 batches), and finally the two
/// lengths that push the block counter to and past index 255 (see `DEEP_COUNTER_BYTES`).
const LENGTHS: &[usize] = &[
    0,
    1,
    2,
    15,
    31,
    32,
    33,
    63,
    64,
    65,
    95,
    96,
    97,
    127,
    128,
    129,
    130,
    159,
    160,
    161,
    255,
    256,
    257,
    384,
    1000,
    4096,
    BOUNDARY_COUNTER_BYTES,
    DEEP_COUNTER_BYTES,
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
            // Stride > max(LENGTHS) so (set_idx, len) -> seed stays injective: a reported
            // "set N, len L" always names exactly one plaintext.
            fill_deterministic(0x3000 + (set_idx as u64) * 100_000 + len as u64, &mut pt);

            // Every output buffer starts DIRTY, with a different pattern per implementation.
            // A zeroed buffer cannot tell `ct[i] = pt[i] ^ ks[i]` apart from `ct[i] ^= ...`,
            // because 0 is the XOR identity — and `crypto::encrypt` is `pub` and takes a
            // caller-supplied `out`, so a reused or uninitialised buffer is a real caller. With
            // distinct prefills, any implementation that accumulates instead of assigning carries
            // its own pattern out and diverges from the other two.
            let mut avx2_out = vec![0xAAu8; len];
            // SAFETY: guarded by the `has_avx2()` check above; `pt` and `avx2_out` are equal length.
            unsafe {
                xor_keystream_avx2(key, nonce, &pt, &mut avx2_out);
            }

            let mut portable_out = vec![0x55u8; len];
            <Portable as TweakAeadStreamOps>::xor_keystream(key, nonce, &pt, &mut portable_out);

            let mut naive_out = vec![0x33u8; len];
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

    // Guard the table's CEILING, not just its floor. The `batched_vectors` floor above only
    // proves the batched loop is entered; it says nothing about how far the block counter is
    // driven inside it. With a 4096-byte maximum the batched loop never saw an index above 127,
    // so a counter narrowed to 8 bits was indistinguishable from the correct `u64`.
    //
    // This checks `LENGTHS` itself, not how many (key/nonce set, length) pairs it produces: the
    // property that matters is that at least one length reaches past block index 255, and that
    // does not get any truer or falser depending on how many key/nonce sets `key_nonce_sets()`
    // happens to return. Counting pairs coupled the guard to `key_nonce_sets()`'s cardinality for
    // no reason — trimming that function's loop for runtime would trip this assertion while
    // `LENGTHS` and its deep-counter coverage stayed exactly as they were.
    assert!(
        LENGTHS.iter().any(|&len| batched_blocks(len) > 256),
        "no length in LENGTHS drives the AVX2 BATCHED loop past block index 255: a block counter \
         narrowed below 64 bits would pass unnoticed (needs a length with batched_blocks(len) > \
         256, i.e. >= 260 full blocks == {} bytes)",
        260 * BLOCK_BYTES
    );
}

/// `xor_keystream_avx2` must **assign** into `ct`, never XOR-accumulate into it.
///
/// The distinction is invisible to any test whose output buffer starts zeroed, because 0 is the
/// identity for XOR: `0 ^ x == x`, so `ct[i] = x` and `ct[i] ^= x` agree byte for byte. Every
/// buffer in this crate's test suite used to be freshly zeroed, and changing both AVX2 write
/// sites to `^=` left all 12 tests green.
///
/// It matters because the buffer is the CALLER's. `crypto::encrypt` is `pub` in a `pub mod
/// crypto` and writes into a caller-supplied `out`; a caller that reuses one buffer across
/// messages — the obvious thing to do to avoid reallocating — would get ciphertext silently
/// XORed with the previous message's, which for a stream cipher leaks the XOR of two plaintexts.
///
/// Stated without reference to the portable path on purpose: encrypting the same input into a
/// clean and a dirty buffer must give the same bytes, whatever those bytes are.
#[test]
fn avx2_output_is_assigned_not_xor_accumulated() {
    // SAFETY GATE: see `avx2_keystream_matches_portable_over_lengths_and_keys`.
    if !has_avx2() {
        return;
    }

    let key = [0x11u8; KEY_BYTES];
    let nonce = [0x22u8; NONCE_BYTES];

    // 297 bytes = 9 full blocks + 9: two iterations of the 4-way batched loop (blocks 0..8), one
    // iteration of the single-block tail (block 8) and a 9-byte remainder (block 9), so all
    // three of the function's write sites run over dirty memory.
    let mut pt = vec![0u8; 297];
    fill_deterministic(0x0000_D147, &mut pt);

    let mut from_clean = vec![0u8; pt.len()];
    // SAFETY: guarded by the `has_avx2()` check above; buffers are equal length.
    unsafe {
        xor_keystream_avx2(&key, &nonce, &pt, &mut from_clean);
    }

    // 0xAA / 0x55 are complements, so between them every bit position is set in one run: an
    // accumulate defect cannot cancel out for both.
    for dirt in [0xAAu8, 0x55u8, 0xFFu8] {
        let mut from_dirty = vec![dirt; pt.len()];
        // SAFETY: guarded by the `has_avx2()` check above; buffers are equal length.
        unsafe {
            xor_keystream_avx2(&key, &nonce, &pt, &mut from_dirty);
        }
        assert_eq!(
            from_dirty,
            from_clean,
            "output depends on what was already in `ct` (prefill {:#04x}, first differing byte \
             {:?}): the AVX2 path is XOR-accumulating into the caller's buffer instead of \
             assigning",
            dirt,
            first_diff(&from_dirty, &from_clean)
        );
    }
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
