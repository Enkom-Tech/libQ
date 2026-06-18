//! ARMv8 (aarch64) AES backend for Rocca-S.
//!
//! ARM splits the AES round: `AESE(x, 0)` performs `ShiftRows(SubBytes(x))` (the
//! AddRoundKey operand is zero here) and `AESMC` performs `MixColumns`, so
//! `AESMC(AESE(x, 0)) ^ k == MixColumns(ShiftRows(SubBytes(x))) ^ k == A(x, k)`,
//! the same AES round as the scalar and AES-NI backends. Outputs are bit-for-bit
//! identical (enforced by `tests/simd_equivalence.rs`).

use core::arch::aarch64::*;

use crate::state::{
    ROUNDS,
    Z0,
    Z1,
};

#[inline(always)]
unsafe fn ld(b: &[u8]) -> uint8x16_t {
    unsafe { vld1q_u8(b.as_ptr()) }
}

#[inline(always)]
unsafe fn st(v: uint8x16_t, out: &mut [u8]) {
    unsafe { vst1q_u8(out.as_mut_ptr(), v) }
}

/// `A(x, k) = MixColumns(ShiftRows(SubBytes(x))) ^ k`.
#[inline(always)]
unsafe fn round(x: uint8x16_t, k: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(vaesmcq_u8(vaeseq_u8(x, vdupq_n_u8(0))), k) }
}

struct State {
    b: [uint8x16_t; 7],
}

impl State {
    #[inline(always)]
    unsafe fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        unsafe {
            let k0 = ld(&key[0..16]);
            let k1 = ld(&key[16..32]);
            let n = ld(nonce);
            let z0 = ld(&Z0);
            let z1 = ld(&Z1);
            let zero = vdupq_n_u8(0);
            let mut s = State {
                b: [k1, n, z0, k0, z1, veorq_u8(n, k1), zero],
            };
            for _ in 0..ROUNDS {
                s.update(z0, z1);
            }
            s.b[0] = veorq_u8(s.b[0], k0);
            s.b[1] = veorq_u8(s.b[1], k0);
            s.b[2] = veorq_u8(s.b[2], k1);
            s.b[3] = veorq_u8(s.b[3], k0);
            s.b[4] = veorq_u8(s.b[4], k0);
            s.b[5] = veorq_u8(s.b[5], k1);
            s.b[6] = veorq_u8(s.b[6], k1);
            s
        }
    }

    #[inline(always)]
    unsafe fn update(&mut self, x0: uint8x16_t, x1: uint8x16_t) {
        unsafe {
            let b = self.b;
            self.b = [
                veorq_u8(b[6], b[1]),
                round(b[0], x0),
                round(b[1], b[0]),
                round(b[2], b[6]),
                round(b[3], x1),
                round(b[4], b[3]),
                round(b[5], b[4]),
            ];
        }
    }

    #[inline(always)]
    unsafe fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        unsafe {
            let b = self.b;
            let m0 = ld(&src[0..16]);
            let m1 = ld(&src[16..32]);
            let c0 = veorq_u8(round(veorq_u8(b[3], b[5]), b[0]), m0);
            let c1 = veorq_u8(round(veorq_u8(b[4], b[6]), b[2]), m1);
            st(c0, &mut dst[0..16]);
            st(c1, &mut dst[16..32]);
            self.update(m0, m1);
        }
    }

    #[inline(always)]
    unsafe fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        unsafe {
            let b = self.b;
            let c0 = ld(&src[0..16]);
            let c1 = ld(&src[16..32]);
            let m0 = veorq_u8(round(veorq_u8(b[3], b[5]), b[0]), c0);
            let m1 = veorq_u8(round(veorq_u8(b[4], b[6]), b[2]), c1);
            st(m0, &mut dst[0..16]);
            st(m1, &mut dst[16..32]);
            self.update(m0, m1);
        }
    }

    #[inline(always)]
    unsafe fn dec_partial(&mut self, dst: &mut [u8; 32], src: &[u8; 32], n: usize) {
        unsafe {
            let b = self.b;
            let c0 = ld(&src[0..16]);
            let c1 = ld(&src[16..32]);
            let m0 = veorq_u8(round(veorq_u8(b[3], b[5]), b[0]), c0);
            let m1 = veorq_u8(round(veorq_u8(b[4], b[6]), b[2]), c1);
            let mut p = [0u8; 32];
            st(m0, &mut p[0..16]);
            st(m1, &mut p[16..32]);
            for byte in p.iter_mut().skip(n) {
                *byte = 0;
            }
            *dst = p;
            self.update(ld(&p[0..16]), ld(&p[16..32]));
        }
    }

    #[inline(always)]
    unsafe fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 32] {
        unsafe {
            let ad_bits = ((ad_len as u128) * 8).to_le_bytes();
            let msg_bits = ((msg_len as u128) * 8).to_le_bytes();
            let a = ld(&ad_bits);
            let m = ld(&msg_bits);
            for _ in 0..ROUNDS {
                self.update(a, m);
            }
            let b = self.b;
            let t0 = veorq_u8(veorq_u8(b[0], b[1]), veorq_u8(b[2], b[3]));
            let t1 = veorq_u8(veorq_u8(b[4], b[5]), b[6]);
            let mut tag = [0u8; 32];
            st(t0, &mut tag[0..16]);
            st(t1, &mut tag[16..32]);
            tag
        }
    }
}

#[inline(always)]
unsafe fn absorb_ad(state: &mut State, ad: &[u8]) {
    unsafe {
        let mut i = 0;
        while i + 32 <= ad.len() {
            state.update(ld(&ad[i..i + 16]), ld(&ad[i + 16..i + 32]));
            i += 32;
        }
        if i < ad.len() {
            let mut pad = [0u8; 32];
            pad[..ad.len() - i].copy_from_slice(&ad[i..]);
            state.update(ld(&pad[0..16]), ld(&pad[16..32]));
        }
    }
}

/// ARMv8 AES Rocca-S encryption. See [`crate::state::encrypt`] for semantics.
#[target_feature(enable = "aes,neon")]
pub(crate) unsafe fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    unsafe {
        let mut state = State::new(key, nonce);
        absorb_ad(&mut state, ad);

        let mut i = 0;
        let mut dst = [0u8; 32];
        while i + 32 <= plaintext.len() {
            let mut src = [0u8; 32];
            src.copy_from_slice(&plaintext[i..i + 32]);
            state.enc(&mut dst, &src);
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
}

/// ARMv8 AES Rocca-S decryption. See [`crate::state::decrypt`] for semantics.
#[target_feature(enable = "aes,neon")]
pub(crate) unsafe fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> [u8; 32] {
    unsafe {
        let mut state = State::new(key, nonce);
        absorb_ad(&mut state, ad);

        let mut i = 0;
        let mut dst = [0u8; 32];
        while i + 32 <= ciphertext.len() {
            let mut src = [0u8; 32];
            src.copy_from_slice(&ciphertext[i..i + 32]);
            state.dec(&mut dst, &src);
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
}
