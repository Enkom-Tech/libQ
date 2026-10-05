//! AEGIS-256 (RFC 10032, Section 4).
//!
//! 768-bit state of six AES blocks; 256-bit key; 256-bit nonce; 128- or 256-bit
//! tag. The core below is written once over [`Block`] and monomorphised per
//! backend. Associated data and message are processed in 128-bit blocks; the
//! final partial block is zero-padded, and on decryption the recovered plaintext
//! tail is zeroed before it is absorbed (RFC 10032, Section 4.8).

use lib_q_intrinsics::aes_round::AesBlock as Block;
use lib_q_intrinsics::aes_round::soft::Soft;

use crate::dispatch::dispatch;

/// AEGIS-256 key size in bytes.
pub const KEY_SIZE: usize = 32;
/// AEGIS-256 nonce size in bytes.
pub const NONCE_SIZE: usize = 32;

/// RFC 10032 constant C0 (Fibonacci sequence mod 256).
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0D, 0x15, 0x22, 0x37, 0x59, 0x90, 0xE9, 0x79, 0x62,
];
/// RFC 10032 constant C1.
const C1: [u8; 16] = [
    0xDB, 0x3D, 0x18, 0x55, 0x6D, 0xC2, 0x2F, 0xF1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xB5, 0x28, 0xDD,
];

struct State<B: Block> {
    s: [B; 6],
}

impl<B: Block> State<B> {
    /// `Update(M)`: six independent AES rounds.
    #[inline(always)]
    unsafe fn update(&mut self, m: B) {
        unsafe {
            let s = self.s;
            self.s = B::round_n(
                [s[5], s[0], s[1], s[2], s[3], s[4]],
                [s[0].xor(m), s[1], s[2], s[3], s[4], s[5]],
            );
        }
    }

    /// `Init(key, nonce)`.
    #[inline(always)]
    unsafe fn new(key: &[u8; 32], nonce: &[u8; 32]) -> Self {
        unsafe {
            let k0 = B::load(first_half(key));
            let k1 = B::load(second_half(key));
            let n0 = B::load(first_half(nonce));
            let n1 = B::load(second_half(nonce));
            let c0 = B::load(&C0);
            let c1 = B::load(&C1);
            let k0n0 = k0.xor(n0);
            let k1n1 = k1.xor(n1);
            let mut st = State {
                s: [k0n0, k1n1, c1, c0, k0.xor(c0), k1.xor(c1)],
            };
            for _ in 0..4 {
                st.update(k0);
                st.update(k1);
                st.update(k0n0);
                st.update(k1n1);
            }
            st
        }
    }

    /// Keystream block `z = S1 ^ S4 ^ S5 ^ (S2 & S3)`.
    #[inline(always)]
    unsafe fn z(&self) -> B {
        unsafe {
            let s = &self.s;
            s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]))
        }
    }

    #[inline(always)]
    unsafe fn absorb(&mut self, ai: &[u8; 16]) {
        unsafe { self.update(B::load(ai)) }
    }

    /// `Enc(xi)` in place.
    #[inline(always)]
    unsafe fn enc(&mut self, blk: &mut [u8; 16]) {
        unsafe {
            let z = self.z();
            let xi = B::load(blk);
            self.update(xi);
            *blk = xi.xor(z).store();
        }
    }

    /// `Dec(ci)` in place.
    #[inline(always)]
    unsafe fn dec(&mut self, blk: &mut [u8; 16]) {
        unsafe {
            let xi = B::load(blk).xor(self.z());
            self.update(xi);
            *blk = xi.store();
        }
    }

    /// `DecPartial(cn)` in place, `tail.len() < 16`.
    #[inline(always)]
    unsafe fn dec_partial(&mut self, tail: &mut [u8]) {
        unsafe {
            let n = tail.len();
            let mut pad = [0u8; 16];
            pad[..n].copy_from_slice(tail);
            let mut out = B::load(&pad).xor(self.z()).store();
            out[n..].fill(0);
            tail.copy_from_slice(&out[..n]);
            self.update(B::load(&out));
        }
    }

    /// `Finalize(ad_len_bits, msg_len_bits)`; `T` is 16 or 32.
    #[inline(always)]
    unsafe fn finalize<const T: usize>(&mut self, ad_len: usize, msg_len: usize) -> [u8; T] {
        unsafe {
            let mut lens = [0u8; 16];
            lens[..8].copy_from_slice(&(ad_len as u64).wrapping_mul(8).to_le_bytes());
            lens[8..].copy_from_slice(&(msg_len as u64).wrapping_mul(8).to_le_bytes());
            let t = self.s[3].xor(B::load(&lens));
            for _ in 0..7 {
                self.update(t);
            }
            let s = &self.s;
            let mut tag = [0u8; T];
            if T == 16 {
                let t0 = s[0]
                    .xor(s[1])
                    .xor(s[2])
                    .xor(s[3])
                    .xor(s[4])
                    .xor(s[5])
                    .store();
                tag.copy_from_slice(&t0);
            } else {
                let t0 = s[0].xor(s[1]).xor(s[2]).store();
                let t1 = s[3].xor(s[4]).xor(s[5]).store();
                tag[..16].copy_from_slice(&t0);
                tag[16..].copy_from_slice(&t1);
            }
            tag
        }
    }

    /// Overwrite the key-dependent state.
    #[inline(always)]
    unsafe fn wipe(&mut self) {
        unsafe {
            let z = B::zero();
            for b in self.s.iter_mut() {
                // Volatile so the store is not elided as dead.
                core::ptr::write_volatile(b, z);
            }
        }
    }
}

#[inline(always)]
fn first_half(x: &[u8; 32]) -> &[u8; 16] {
    &x.as_chunks::<16>().0[0]
}

#[inline(always)]
fn second_half(x: &[u8; 32]) -> &[u8; 16] {
    &x.as_chunks::<16>().0[1]
}

#[inline(always)]
unsafe fn absorb_ad<B: Block>(st: &mut State<B>, ad: &[u8]) {
    unsafe {
        let (blocks, rem) = ad.as_chunks::<16>();
        for blk in blocks {
            st.absorb(blk);
        }
        if !rem.is_empty() {
            let mut pad = [0u8; 16];
            pad[..rem.len()].copy_from_slice(rem);
            st.absorb(&pad);
        }
    }
}

/// Encrypt `buf` in place and return the tag.
#[inline(always)]
unsafe fn seal<B: Block, const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    unsafe {
        let mut st = State::<B>::new(key, nonce);
        absorb_ad(&mut st, ad);
        let msg_len = buf.len();
        let (blocks, rem) = buf.as_chunks_mut::<16>();
        for blk in blocks {
            st.enc(blk);
        }
        if !rem.is_empty() {
            let mut pad = [0u8; 16];
            pad[..rem.len()].copy_from_slice(rem);
            st.enc(&mut pad);
            let n = rem.len();
            rem.copy_from_slice(&pad[..n]);
        }
        let tag = st.finalize::<T>(ad.len(), msg_len);
        st.wipe();
        tag
    }
}

/// Decrypt `buf` in place and return the recomputed tag. The caller compares the
/// tag in constant time and zeroes `buf` on mismatch.
#[inline(always)]
unsafe fn open<B: Block, const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    unsafe {
        let mut st = State::<B>::new(key, nonce);
        absorb_ad(&mut st, ad);
        let msg_len = buf.len();
        let (blocks, rem) = buf.as_chunks_mut::<16>();
        for blk in blocks {
            st.dec(blk);
        }
        if !rem.is_empty() {
            st.dec_partial(rem);
        }
        let tag = st.finalize::<T>(ad.len(), msg_len);
        st.wipe();
        tag
    }
}

#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "aes,sse2")]
unsafe fn seal_aesni<const T: usize>(
    k: &[u8; 32],
    n: &[u8; 32],
    ad: &[u8],
    b: &mut [u8],
) -> [u8; T] {
    unsafe { seal::<lib_q_intrinsics::aes_round::aesni::Ni, T>(k, n, ad, b) }
}

#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "aes,sse2")]
unsafe fn open_aesni<const T: usize>(
    k: &[u8; 32],
    n: &[u8; 32],
    ad: &[u8],
    b: &mut [u8],
) -> [u8; T] {
    unsafe { open::<lib_q_intrinsics::aes_round::aesni::Ni, T>(k, n, ad, b) }
}

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn seal_neon<const T: usize>(
    k: &[u8; 32],
    n: &[u8; 32],
    ad: &[u8],
    b: &mut [u8],
) -> [u8; T] {
    unsafe { seal::<lib_q_intrinsics::aes_round::neon::Neon, T>(k, n, ad, b) }
}

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn open_neon<const T: usize>(
    k: &[u8; 32],
    n: &[u8; 32],
    ad: &[u8],
    b: &mut [u8],
) -> [u8; T] {
    unsafe { open::<lib_q_intrinsics::aes_round::neon::Neon, T>(k, n, ad, b) }
}

/// Encrypt in place on the fastest available backend; returns the `T`-byte tag.
pub(crate) fn seal_dispatch<const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    dispatch!(
        aesni => seal_aesni::<T>(key, nonce, ad, buf),
        neon => seal_neon::<T>(key, nonce, ad, buf),
        // SAFETY: the software backend has no CPU-feature requirements.
        soft => unsafe { seal::<Soft, T>(key, nonce, ad, buf) },
    )
}

/// Decrypt in place on the fastest available backend; returns the expected tag.
pub(crate) fn open_dispatch<const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    dispatch!(
        aesni => open_aesni::<T>(key, nonce, ad, buf),
        neon => open_neon::<T>(key, nonce, ad, buf),
        // SAFETY: the software backend has no CPU-feature requirements.
        soft => unsafe { open::<Soft, T>(key, nonce, ad, buf) },
    )
}

/// Portable-backend seal, for cross-backend equivalence tests.
pub(crate) fn seal_soft<const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    // SAFETY: the software backend has no CPU-feature requirements.
    unsafe { seal::<Soft, T>(key, nonce, ad, buf) }
}

/// Portable-backend open, for cross-backend equivalence tests.
pub(crate) fn open_soft<const T: usize>(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; T] {
    // SAFETY: the software backend has no CPU-feature requirements.
    unsafe { open::<Soft, T>(key, nonce, ad, buf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h16(s: &str) -> [u8; 16] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    /// RFC 10032 Appendix A.3.1 (Update test vector), on the portable backend.
    #[test]
    fn rfc10032_update_vector() {
        let s_in = [
            "1fa1207ed76c86f2c4bb40e8b395b43e",
            "b44c375e6c1e1978db64bcd12e9e332f",
            "0dab84bfa9f0226432ff630f233d4e5b",
            "d7ef65c9b93e8ee60c75161407b066e7",
            "a760bb3da073fbd92bdc24734b1f56fb",
            "a828a18d6a964497ac6e7e53c5f55c73",
        ];
        let m = "b165617ed04ab738afb2612c6d18a1ec";
        let s_out = [
            "e6bc643bae82dfa3d991b1b323839dcd",
            "648578232ba0f2f0a3677f617dc052c3",
            "ea788e0e572044a46059212dd007a789",
            "2f1498ae19b80da13fba698f088a8590",
            "a54c2ee95e8c2a2c3dae2ec743ae6b86",
            "a3240fceb68e32d5d114df1b5363ab67",
        ];
        let mut st = State::<Soft> {
            s: s_in.map(|h| Soft(h16(h))),
        };
        // SAFETY: software backend.
        unsafe { st.update(Soft(h16(m))) };
        for (got, want) in st.s.iter().zip(s_out) {
            assert_eq!(got.0, h16(want));
        }
    }
}
