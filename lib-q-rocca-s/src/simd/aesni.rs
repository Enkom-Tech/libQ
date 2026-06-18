//! x86 / x86_64 AES-NI backend for Rocca-S.
//!
//! `_mm_aesenc_si128(x, k)` computes `MixColumns(ShiftRows(SubBytes(x))) ^ k`,
//! exactly the AES round `A(x, k)` used throughout Rocca-S. The 128-bit register
//! byte order matches the scalar backend's column-major mapping, so outputs are
//! identical (enforced by `tests/simd_equivalence.rs`).
//!
//! Each entry point is a single `#[target_feature(enable = "aes,sse2")]` function
//! so the intrinsics inline; callers reach them only after [`super::runtime::has_aes`].

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::state::{
    ROUNDS,
    Z0,
    Z1,
};

#[inline(always)]
unsafe fn ld(b: &[u8]) -> __m128i {
    unsafe { _mm_loadu_si128(b.as_ptr() as *const __m128i) }
}

#[inline(always)]
unsafe fn st(v: __m128i, out: &mut [u8]) {
    unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v) }
}

struct State {
    b: [__m128i; 7],
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
            let zero = _mm_setzero_si128();
            let mut s = State {
                b: [k1, n, z0, k0, z1, _mm_xor_si128(n, k1), zero],
            };
            for _ in 0..ROUNDS {
                s.update(z0, z1);
            }
            s.b[0] = _mm_xor_si128(s.b[0], k0);
            s.b[1] = _mm_xor_si128(s.b[1], k0);
            s.b[2] = _mm_xor_si128(s.b[2], k1);
            s.b[3] = _mm_xor_si128(s.b[3], k0);
            s.b[4] = _mm_xor_si128(s.b[4], k0);
            s.b[5] = _mm_xor_si128(s.b[5], k1);
            s.b[6] = _mm_xor_si128(s.b[6], k1);
            s
        }
    }

    #[inline(always)]
    unsafe fn update(&mut self, x0: __m128i, x1: __m128i) {
        unsafe {
            let b = self.b;
            self.b = [
                _mm_xor_si128(b[6], b[1]),
                _mm_aesenc_si128(b[0], x0),
                _mm_aesenc_si128(b[1], b[0]),
                _mm_aesenc_si128(b[2], b[6]),
                _mm_aesenc_si128(b[3], x1),
                _mm_aesenc_si128(b[4], b[3]),
                _mm_aesenc_si128(b[5], b[4]),
            ];
        }
    }

    #[inline(always)]
    unsafe fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        unsafe {
            let b = self.b;
            let m0 = ld(&src[0..16]);
            let m1 = ld(&src[16..32]);
            let c0 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[3], b[5]), b[0]), m0);
            let c1 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[4], b[6]), b[2]), m1);
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
            let m0 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[3], b[5]), b[0]), c0);
            let m1 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[4], b[6]), b[2]), c1);
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
            let m0 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[3], b[5]), b[0]), c0);
            let m1 = _mm_xor_si128(_mm_aesenc_si128(_mm_xor_si128(b[4], b[6]), b[2]), c1);
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
            let t0 = _mm_xor_si128(_mm_xor_si128(b[0], b[1]), _mm_xor_si128(b[2], b[3]));
            let t1 = _mm_xor_si128(_mm_xor_si128(b[4], b[5]), b[6]);
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
            let a0 = ld(&ad[i..i + 16]);
            let a1 = ld(&ad[i + 16..i + 32]);
            state.update(a0, a1);
            i += 32;
        }
        if i < ad.len() {
            let mut pad = [0u8; 32];
            pad[..ad.len() - i].copy_from_slice(&ad[i..]);
            state.update(ld(&pad[0..16]), ld(&pad[16..32]));
        }
    }
}

/// AES-NI Rocca-S encryption. See [`crate::state::encrypt`] for semantics.
#[target_feature(enable = "aes,sse2")]
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

/// AES-NI Rocca-S decryption. See [`crate::state::decrypt`] for semantics.
#[target_feature(enable = "aes,sse2")]
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
