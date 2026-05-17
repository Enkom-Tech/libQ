//! Portable keystream XOR.

use crate::block::keystream_block;
use crate::params::{
    BLOCK_BYTES,
    KEY_BYTES,
    NONCE_BYTES,
};
use crate::simd::traits::TweakAeadStreamOps;

pub struct Portable;

impl TweakAeadStreamOps for Portable {
    fn xor_keystream(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], pt: &[u8], ct: &mut [u8]) {
        debug_assert_eq!(pt.len(), ct.len());
        let full_blocks = pt.len() / BLOCK_BYTES;
        for b in 0..full_blocks {
            let ks = keystream_block(key, nonce, b as u64);
            let base = b * BLOCK_BYTES;
            for j in 0..BLOCK_BYTES {
                ct[base + j] = pt[base + j] ^ ks[j];
            }
        }
        let rem = pt.len() % BLOCK_BYTES;
        if rem > 0 {
            let b = full_blocks as u64;
            let ks = keystream_block(key, nonce, b);
            let base = full_blocks * BLOCK_BYTES;
            for j in 0..rem {
                ct[base + j] = pt[base + j] ^ ks[j];
            }
        }
    }
}
