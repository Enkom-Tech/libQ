//! AVX2 fast path: batched Keccak-f[1600] for four consecutive block counters.
#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;

use crate::block::setup_state_pre_f1600;
use crate::params::{
    BLOCK_BYTES,
    KEY_BYTES,
    NONCE_BYTES,
    PLEN,
};
use crate::simd::avx2_keccak::{
    f1600_x4,
    transpose_from_x4,
    transpose_to_x4,
};
use crate::sponge::first_32_from_state;

/// XOR keystream for plaintext slice using AVX2 batched permutation when possible.
/// Caller must ensure `has_avx2()` is true.
#[target_feature(enable = "avx2")]
pub unsafe fn xor_keystream_avx2(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    pt: &[u8],
    ct: &mut [u8],
) {
    debug_assert_eq!(pt.len(), ct.len());
    let full_blocks = pt.len() / BLOCK_BYTES;
    let mut block_idx = 0u64;
    let mut byte_off = 0usize;

    let mut vx: [__m256i; PLEN] = [_mm256_setzero_si256(); PLEN];

    while block_idx + 4 <= full_blocks as u64 {
        let mut states = [[0u64; PLEN]; 4];
        for i in 0..4 {
            setup_state_pre_f1600(&mut states[i], key, nonce, block_idx + i as u64);
        }
        transpose_to_x4(&states, &mut vx);
        f1600_x4(&mut vx);
        transpose_from_x4(&vx, &mut states);
        for i in 0..4 {
            let ks = first_32_from_state(&states[i]);
            let base = byte_off + i * BLOCK_BYTES;
            for j in 0..BLOCK_BYTES {
                ct[base + j] = pt[base + j] ^ ks[j];
            }
        }
        block_idx += 4;
        byte_off += 4 * BLOCK_BYTES;
    }

    while block_idx < full_blocks as u64 {
        let ks = crate::block::keystream_block(key, nonce, block_idx);
        let base = byte_off;
        for j in 0..BLOCK_BYTES {
            ct[base + j] = pt[base + j] ^ ks[j];
        }
        block_idx += 1;
        byte_off += BLOCK_BYTES;
    }

    let rem = pt.len() - byte_off;
    if rem > 0 {
        let ks = crate::block::keystream_block(key, nonce, block_idx);
        for j in 0..rem {
            ct[byte_off + j] = pt[byte_off + j] ^ ks[j];
        }
    }
}
