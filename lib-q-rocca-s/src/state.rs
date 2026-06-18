//! Rocca-S state and AEAD core (scalar backend).
//!
//! Faithful port of the IETF draft Rocca-S (`draft-nakano-rocca-s`), matching the
//! reference implementation at <https://github.com/jedisct1/rust-rocca-s>. The
//! round schedule, initialization, keystream and finalization here are pinned by
//! the official all-zero KAT (see `tests/kat_tests.rs`).
//!
//! Parameters: 256-bit key, 128-bit nonce, 256-bit (32-byte) tag. Associated data
//! and message are processed in 256-bit (two AES-block) chunks; the final partial
//! chunk is zero-padded, and for decryption the recovered plaintext tail is zeroed
//! before the state update so encryption and decryption stay in lock-step.

use crate::round::aes_round;

/// Number of update rounds in initialization and finalization.
pub(crate) const ROUNDS: usize = 16;

/// Z0 initialization constant (IETF Rocca-S).
pub(crate) const Z0: [u8; 16] = [
    205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66,
];
/// Z1 initialization constant (IETF Rocca-S).
pub(crate) const Z1: [u8; 16] = [
    188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181,
];

type Block = [u8; 16];

#[inline(always)]
fn xor(a: Block, b: Block) -> Block {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

#[inline(always)]
fn block(src: &[u8]) -> Block {
    let mut b = [0u8; 16];
    b.copy_from_slice(src);
    b
}

/// The seven-block Rocca-S state.
pub(crate) struct State {
    blocks: [Block; 7],
}

impl State {
    /// Initialize from a 256-bit key and 128-bit nonce.
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let k0 = block(&key[0..16]);
        let k1 = block(&key[16..32]);
        let n = *nonce;
        let zero = [0u8; 16];

        let blocks = [k1, n, Z0, k0, Z1, xor(n, k1), zero];
        let mut state = State { blocks };
        for _ in 0..ROUNDS {
            state.update(Z0, Z1);
        }
        state.blocks[0] = xor(state.blocks[0], k0);
        state.blocks[1] = xor(state.blocks[1], k0);
        state.blocks[2] = xor(state.blocks[2], k1);
        state.blocks[3] = xor(state.blocks[3], k0);
        state.blocks[4] = xor(state.blocks[4], k0);
        state.blocks[5] = xor(state.blocks[5], k1);
        state.blocks[6] = xor(state.blocks[6], k1);
        state
    }

    /// Rocca-S round update with the two 128-bit inputs `x0`, `x1`.
    #[inline]
    fn update(&mut self, x0: Block, x1: Block) {
        let b = &self.blocks;
        let next = [
            xor(b[6], b[1]),
            aes_round(&b[0], &x0),
            aes_round(&b[1], &b[0]),
            aes_round(&b[2], &b[6]),
            aes_round(&b[3], &x1),
            aes_round(&b[4], &b[3]),
            aes_round(&b[5], &b[4]),
        ];
        self.blocks = next;
    }

    /// Absorb one 256-bit associated-data chunk (no output).
    #[inline]
    fn absorb(&mut self, chunk: &[u8; 32]) {
        let a0 = block(&chunk[0..16]);
        let a1 = block(&chunk[16..32]);
        self.update(a0, a1);
    }

    /// Encrypt one 256-bit plaintext chunk into `dst`.
    #[inline]
    fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let b = &self.blocks;
        let m0 = block(&src[0..16]);
        let m1 = block(&src[16..32]);
        let c0 = xor(aes_round(&xor(b[3], b[5]), &b[0]), m0);
        let c1 = xor(aes_round(&xor(b[4], b[6]), &b[2]), m1);
        dst[0..16].copy_from_slice(&c0);
        dst[16..32].copy_from_slice(&c1);
        self.update(m0, m1);
    }

    /// Decrypt one 256-bit ciphertext chunk into `dst`.
    #[inline]
    fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let b = &self.blocks;
        let c0 = block(&src[0..16]);
        let c1 = block(&src[16..32]);
        let m0 = xor(aes_round(&xor(b[3], b[5]), &b[0]), c0);
        let m1 = xor(aes_round(&xor(b[4], b[6]), &b[2]), c1);
        dst[0..16].copy_from_slice(&m0);
        dst[16..32].copy_from_slice(&m1);
        self.update(m0, m1);
    }

    /// Decrypt a final partial chunk of `n` (< 32) bytes; the recovered plaintext
    /// tail is zeroed before the state update so it matches the zero-padded
    /// plaintext used during encryption.
    #[inline]
    fn dec_partial(&mut self, dst: &mut [u8; 32], src: &[u8; 32], n: usize) {
        let b = &self.blocks;
        let c0 = block(&src[0..16]);
        let c1 = block(&src[16..32]);
        let m0 = xor(aes_round(&xor(b[3], b[5]), &b[0]), c0);
        let m1 = xor(aes_round(&xor(b[4], b[6]), &b[2]), c1);
        let mut p = [0u8; 32];
        p[0..16].copy_from_slice(&m0);
        p[16..32].copy_from_slice(&m1);
        for byte in p.iter_mut().skip(n) {
            *byte = 0;
        }
        *dst = p;
        self.update(block(&p[0..16]), block(&p[16..32]));
    }

    /// Finalize and produce the 256-bit tag, binding AD and message bit-lengths.
    #[inline]
    fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 32] {
        let ad_bits = ((ad_len as u128) * 8).to_le_bytes();
        let msg_bits = ((msg_len as u128) * 8).to_le_bytes();
        for _ in 0..ROUNDS {
            self.update(ad_bits, msg_bits);
        }
        let b = &self.blocks;
        let t0 = xor(xor(xor(b[0], b[1]), b[2]), b[3]);
        let t1 = xor(xor(b[4], b[5]), b[6]);
        let mut tag = [0u8; 32];
        tag[0..16].copy_from_slice(&t0);
        tag[16..32].copy_from_slice(&t1);
        tag
    }
}

/// Absorb all associated data in 256-bit chunks (final chunk zero-padded).
fn absorb_ad(state: &mut State, ad: &[u8]) {
    let mut i = 0;
    while i + 32 <= ad.len() {
        state.absorb(&block32(&ad[i..i + 32]));
        i += 32;
    }
    if i < ad.len() {
        let mut pad = [0u8; 32];
        pad[..ad.len() - i].copy_from_slice(&ad[i..]);
        state.absorb(&pad);
    }
}

#[inline(always)]
fn block32(src: &[u8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(src);
    b
}

/// Encrypt `plaintext` under `key`/`nonce` with associated data `ad`, writing the
/// ciphertext to `out` (same length as plaintext) and returning the 256-bit tag.
pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    debug_assert_eq!(out.len(), plaintext.len());
    let mut state = State::new(key, nonce);
    absorb_ad(&mut state, ad);

    let mut i = 0;
    let mut dst = [0u8; 32];
    while i + 32 <= plaintext.len() {
        state.enc(&mut dst, &block32(&plaintext[i..i + 32]));
        out[i..i + 32].copy_from_slice(&dst);
        i += 32;
    }
    if i < plaintext.len() {
        let n = plaintext.len() - i;
        let mut src = [0u8; 32];
        src[..n].copy_from_slice(&plaintext[i..]);
        state.enc(&mut dst, &src);
        out[i..].copy_from_slice(&dst[..n]);
    }

    state.finalize(ad.len(), plaintext.len())
}

/// Decrypt `ciphertext` under `key`/`nonce` with associated data `ad`, writing the
/// recovered plaintext to `out` (same length as ciphertext) and returning the
/// recomputed 256-bit tag. The caller is responsible for constant-time tag
/// comparison and for discarding `out` on tag mismatch.
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    debug_assert_eq!(out.len(), ciphertext.len());
    let mut state = State::new(key, nonce);
    absorb_ad(&mut state, ad);

    let mut i = 0;
    let mut dst = [0u8; 32];
    while i + 32 <= ciphertext.len() {
        state.dec(&mut dst, &block32(&ciphertext[i..i + 32]));
        out[i..i + 32].copy_from_slice(&dst);
        i += 32;
    }
    if i < ciphertext.len() {
        let n = ciphertext.len() - i;
        let mut src = [0u8; 32];
        src[..n].copy_from_slice(&ciphertext[i..]);
        state.dec_partial(&mut dst, &src, n);
        out[i..].copy_from_slice(&dst[..n]);
    }

    state.finalize(ad.len(), ciphertext.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_all_zero_kat() {
        let key = [0u8; 32];
        let nonce = [0u8; 16];
        let ad = [0u8; 32];
        let pt = [0u8; 64];
        let mut ct = [0u8; 64];
        let tag = encrypt(&key, &nonce, &ad, &pt, &mut ct);

        let expected_ct = hex32x2(
            "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e4617",
            "0de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb",
        );
        let expected_tag =
            hex32("8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386");
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let mut back = [0u8; 64];
        let tag2 = decrypt(&key, &nonce, &ad, &ct, &mut back);
        assert_eq!(back, pt);
        assert_eq!(tag2, tag);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
    fn hex32x2(a: &str, b: &str) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&hex32(a));
        o[32..].copy_from_slice(&hex32(b));
        o
    }
}
