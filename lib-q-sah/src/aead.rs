//! S-A-H AEAD mode logic (spec sections 5-7).
//!
//! Internal: operates on a raw `[u64; 8]` state plus the 4 key words. The
//! public, typed API lives in `lib.rs`.

use crate::params::*;
use crate::round::permute;
use zeroize::Zeroize;

/// Working state: the 512-bit permutation state and the cached key words used
/// for feedforward and tag extraction. Zeroized on drop.
struct Ctx {
    s: [u64; 8],
    k: [u64; 4],
}

impl Drop for Ctx {
    fn drop(&mut self) {
        self.s.zeroize();
        self.k.zeroize();
    }
}

#[inline(always)]
fn domain_xor(s: &mut [u64; 8], d: u8) {
    s[7] ^= (d as u64) << 56;
}

#[inline(always)]
fn rate_byte(s: &[u64; 8], j: usize) -> u8 {
    (s[j / 8] >> (8 * (j % 8))) as u8
}

#[inline(always)]
fn set_rate_byte(s: &mut [u64; 8], j: usize, v: u8) {
    let shift = 8 * (j % 8);
    s[j / 8] = (s[j / 8] & !(0xFFu64 << shift)) | ((v as u64) << shift);
}

#[inline(always)]
fn xor_rate_byte(s: &mut [u64; 8], j: usize, v: u8) {
    s[j / 8] ^= (v as u64) << (8 * (j % 8));
}

#[inline(always)]
fn read_word_le(b: &[u8], word: usize) -> u64 {
    u64::from_le_bytes(b[8 * word..8 * word + 8].try_into().unwrap())
}

impl Ctx {
    /// Spec section 5: direct key/nonce injection, init permutation, feedforward.
    fn init(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Ctx {
        let mut k = [0u64; 4];
        for (i, kw) in k.iter_mut().enumerate() {
            *kw = read_word_le(key, i);
        }
        let mut s = [0u64; 8];
        s[0..4].copy_from_slice(&k);
        for (i, nw) in s[4..6].iter_mut().enumerate() {
            *nw = read_word_le(nonce, i);
        }
        s[6] = PARAM;
        s[7] = IV;

        domain_xor(&mut s, DOMAIN_INIT);
        permute(&mut s, ROUNDS_INIT);
        for (sw, &kw) in s[4..8].iter_mut().zip(k.iter()) {
            *sw ^= kw;
        }
        Ctx { s, k }
    }

    /// Spec section 6, AAD phase. Caller skips this entirely when `aad` is empty.
    fn absorb_aad(&mut self, aad: &[u8]) {
        let s = &mut self.s;
        let mut off = 0;
        while aad.len() - off >= BLOCK_LEN {
            for (i, sw) in s[0..4].iter_mut().enumerate() {
                *sw ^= read_word_le(&aad[off..], i);
            }
            domain_xor(s, DOMAIN_AAD);
            permute(s, ROUNDS_AAD);
            off += BLOCK_LEN;
        }
        let rem = aad.len() - off;
        // pad10*: `absorb_aad` is only called for non-empty AAD, so the marked
        // final block is always emitted. rem > 0 is a partial block; rem == 0 is a
        // block-aligned length, which emits one extra all-pad block (marker in
        // rate byte 0).
        for j in 0..rem {
            xor_rate_byte(s, j, aad[off + j]);
        }
        xor_rate_byte(s, rem, 0x01);
        domain_xor(s, DOMAIN_AAD);
        permute(s, ROUNDS_AAD);
    }

    /// Spec section 6, message phase. `DECRYPT` selects which of in/out is the
    /// ciphertext that replaces the rate, keeping encrypt/decrypt states synced.
    fn process_message<const DECRYPT: bool>(&mut self, input: &[u8], output: &mut [u8]) {
        let s = &mut self.s;
        let mut off = 0;
        while input.len() - off >= BLOCK_LEN {
            // i indexes the four rate words and their byte offsets (8*i); the
            // explicit index mirrors the spec's block layout.
            #[allow(clippy::needless_range_loop)]
            for i in 0..4 {
                let ks = s[i];
                let in_w = read_word_le(&input[off..], i);
                let out_w = in_w ^ ks;
                output[off + 8 * i..off + 8 * i + 8].copy_from_slice(&out_w.to_le_bytes());
                s[i] = if DECRYPT { in_w } else { out_w };
            }
            domain_xor(s, DOMAIN_MSG);
            permute(s, ROUNDS_MSG);
            off += BLOCK_LEN;
        }
        let rem = input.len() - off;
        // pad10*: only called for non-empty messages, so the marked final block is
        // always emitted (rem == 0 emits an extra all-pad block, no output).
        for j in 0..rem {
            let ks = rate_byte(s, j);
            let out_byte = input[off + j] ^ ks;
            let c_byte = if DECRYPT { input[off + j] } else { out_byte };
            output[off + j] = out_byte;
            set_rate_byte(s, j, c_byte);
        }
        xor_rate_byte(s, rem, 0x01);
        domain_xor(s, DOMAIN_MSG);
        permute(s, ROUNDS_MSG);
    }

    /// Spec section 7: length injection, key feedforward, final permutation, tag.
    fn finalize(&mut self, aad_len: u64, msg_len: u64) -> [u8; TAG_LEN] {
        let s = &mut self.s;
        s[4] ^= aad_len.wrapping_mul(8);
        s[5] ^= msg_len.wrapping_mul(8);
        for (sw, &kw) in s[4..8].iter_mut().zip(self.k.iter()) {
            *sw ^= kw;
        }
        domain_xor(s, DOMAIN_FINAL);
        permute(s, ROUNDS_FINAL);

        let mut tag = [0u8; TAG_LEN];
        tag[0..8].copy_from_slice(&(s[0] ^ self.k[0]).to_le_bytes());
        tag[8..16].copy_from_slice(&(s[1] ^ self.k[1]).to_le_bytes());
        tag
    }
}

/// Encrypt `pt` into `ct` (same length); return the tag. Lengths are assumed
/// valid (checked by the public API).
pub(crate) fn seal_detached(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
) -> [u8; TAG_LEN] {
    debug_assert_eq!(ct.len(), pt.len());
    let mut ctx = Ctx::init(key, nonce);
    if !aad.is_empty() {
        ctx.absorb_aad(aad);
    }
    if !pt.is_empty() {
        ctx.process_message::<false>(pt, ct);
    }
    ctx.finalize(aad.len() as u64, pt.len() as u64)
}

/// Decrypt `ct` into `pt` (same length), verifying `tag` in constant time.
/// Returns the recomputed tag for the caller to compare; the caller owns the
/// constant-time comparison and zeroization-on-failure policy.
pub(crate) fn open_detached_recompute(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    pt: &mut [u8],
) -> [u8; TAG_LEN] {
    debug_assert_eq!(pt.len(), ct.len());
    let mut ctx = Ctx::init(key, nonce);
    if !aad.is_empty() {
        ctx.absorb_aad(aad);
    }
    if !ct.is_empty() {
        ctx.process_message::<true>(ct, pt);
    }
    ctx.finalize(aad.len() as u64, ct.len() as u64)
}
