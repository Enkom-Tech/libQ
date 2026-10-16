//! HiAE (draft-pham-cfrg-hiae-06). **Provisional.**
//!
//! 2048-bit state of sixteen AES blocks; 256-bit key; 128-bit nonce; 128-bit tag
//! (the draft forbids other tag lengths). The core is written once over
//! [`Block`] and monomorphised per backend.
//!
//! `Rol()` is implemented with the cycling-index technique of the draft's
//! Section 7.1: logical block `Si` lives at physical index `(i + off) mod 16`, and
//! `Rol()` only increments `off`. Bulk data is processed in batches of sixteen
//! blocks with the offsets written as literals, so the indexing folds to constants.
//! Between phases the array is rotated back so that `off == 0`; `off` depends only
//! on public lengths, never on secret data.
//!
//! Security model caveat (see `SECURITY.md`): the designers' analysis assumes an
//! adversary cannot submit repeated forgery attempts. Published attacks that use
//! decryption queries recover the key with about 2^128 data and 2^129.6 time
//! (IACR ePrint 2025/1180). Do not deploy HiAE where an adversary can make many
//! decryption queries under one key, which includes any network data plane.

use lib_q_intrinsics::aes_round::AesBlock as Block;
use lib_q_intrinsics::aes_round::soft::Soft;

use crate::dispatch::dispatch;

/// HiAE key size in bytes.
pub const KEY_SIZE: usize = 32;
/// HiAE nonce size in bytes.
pub const NONCE_SIZE: usize = 16;
/// HiAE tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Domain-separation constant C0 (fractional part of pi).
const C0: [u8; 16] = [
    0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
];
/// Domain-separation constant C1 (fractional part of e).
const C1: [u8; 16] = [
    0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D, 0x00, 0x82, 0xEF, 0xA9, 0x8E, 0xC4, 0xE6, 0xC8,
];

#[inline(always)]
const fn ix(off: usize, i: usize) -> usize {
    (i + off) & 15
}

struct State<B: Block> {
    s: [B; 16],
    /// Physical index of logical `S0`.
    off: usize,
}

/// Calls `$st.$op(OFF, &mut $blocks[OFF])` for OFF = 0..16 with literal offsets.
macro_rules! unroll16 {
    ($st:expr, $op:ident, $blocks:expr) => {
        $st.$op(0, &mut $blocks[0]);
        $st.$op(1, &mut $blocks[1]);
        $st.$op(2, &mut $blocks[2]);
        $st.$op(3, &mut $blocks[3]);
        $st.$op(4, &mut $blocks[4]);
        $st.$op(5, &mut $blocks[5]);
        $st.$op(6, &mut $blocks[6]);
        $st.$op(7, &mut $blocks[7]);
        $st.$op(8, &mut $blocks[8]);
        $st.$op(9, &mut $blocks[9]);
        $st.$op(10, &mut $blocks[10]);
        $st.$op(11, &mut $blocks[11]);
        $st.$op(12, &mut $blocks[12]);
        $st.$op(13, &mut $blocks[13]);
        $st.$op(14, &mut $blocks[14]);
        $st.$op(15, &mut $blocks[15]);
    };
}

impl<B: Block> State<B> {
    /// Returns `(AESL(S0 ^ S1), AESL(S13))` on the software backend, where batching
    /// both rounds into one S-box circuit evaluation halves the work.
    #[inline(always)]
    unsafe fn soft_pair(&self, off: usize) -> (B, B) {
        unsafe {
            let s = &self.s;
            let [a, b] = B::round_n(
                [s[ix(off, 0)].xor(s[ix(off, 1)]), s[ix(off, 13)]],
                [B::zero(), B::zero()],
            );
            (a, b)
        }
    }

    /// Writes the new `S0` and absorbs `x` into `S3` and `S13` (the `Rol()` is the
    /// caller's offset increment).
    #[inline(always)]
    unsafe fn commit(&mut self, off: usize, new_s0: B, x: B) {
        unsafe {
            self.s[ix(off, 0)] = new_s0;
            self.s[ix(off, 3)] = self.s[ix(off, 3)].xor(x);
            self.s[ix(off, 13)] = self.s[ix(off, 13)].xor(x);
        }
    }

    /// `Update(xi)` at logical offset `off`.
    #[inline(always)]
    unsafe fn update_at(&mut self, off: usize, xi: B) {
        unsafe {
            let new_s0 = if B::BITSLICED {
                let (a, b) = self.soft_pair(off);
                b.xor(a.xor(xi))
            } else {
                let s = &self.s;
                let t = B::xaesl_x(s[ix(off, 0)], s[ix(off, 1)], xi);
                s[ix(off, 13)].round(t)
            };
            self.commit(off, new_s0, xi);
        }
    }

    /// `Absorb(ai)` at logical offset `off`.
    #[inline(always)]
    unsafe fn absorb_at(&mut self, off: usize, blk: &mut [u8; 16]) {
        unsafe { self.update_at(off, B::load(blk)) }
    }

    /// `UpdateEnc(mi)` in place at logical offset `off`.
    #[inline(always)]
    unsafe fn enc_at(&mut self, off: usize, blk: &mut [u8; 16]) {
        unsafe {
            let mi = B::load(blk);
            let s9 = self.s[ix(off, 9)];
            let (ci, new_s0) = if B::BITSLICED {
                let (a, b) = self.soft_pair(off);
                let t = a.xor(mi);
                (t.xor(s9), b.xor(t))
            } else {
                let s = &self.s;
                // Intel form (draft Section 7.2.2.2): ci = AESL(S0 ^ S1) ^ (mi ^ S9).
                let ci = B::xaesl_x(s[ix(off, 0)], s[ix(off, 1)], mi.xor(s9));
                (ci, s[ix(off, 13)].round(ci.xor(s9)))
            };
            self.commit(off, new_s0, mi);
            *blk = ci.store();
        }
    }

    /// `UpdateDec(ci)` in place at logical offset `off`.
    #[inline(always)]
    unsafe fn dec_at(&mut self, off: usize, blk: &mut [u8; 16]) {
        unsafe {
            let t = B::load(blk).xor(self.s[ix(off, 9)]);
            let (mi, new_s0) = if B::BITSLICED {
                let (a, b) = self.soft_pair(off);
                (a.xor(t), b.xor(t))
            } else {
                let s = &self.s;
                (
                    B::xaesl_x(s[ix(off, 0)], s[ix(off, 1)], t),
                    s[ix(off, 13)].round(t),
                )
            };
            self.commit(off, new_s0, mi);
            *blk = mi.store();
        }
    }

    /// Runtime-offset step for the unaligned head/tail of a phase.
    #[inline(always)]
    unsafe fn step(&mut self, op: Op, blk: &mut [u8; 16]) {
        unsafe {
            let off = self.off;
            match op {
                Op::Absorb => self.absorb_at(off, blk),
                Op::Enc => self.enc_at(off, blk),
                Op::Dec => self.dec_at(off, blk),
            }
            self.off = ix(off, 1);
        }
    }

    /// Rotate the physical array so logical `S0` is at index 0.
    #[inline(always)]
    fn realign(&mut self) {
        let off = self.off;
        self.s.rotate_left(off);
        self.off = 0;
    }

    /// Process whole blocks: aligned batches of 16 with literal offsets, then the rest.
    #[inline(always)]
    unsafe fn blocks(&mut self, op: Op, blocks: &mut [[u8; 16]]) {
        unsafe {
            self.realign();
            let (batches, rest) = blocks.as_chunks_mut::<16>();
            for b in batches {
                match op {
                    Op::Absorb => {
                        unroll16!(self, absorb_at, b);
                    }
                    Op::Enc => {
                        unroll16!(self, enc_at, b);
                    }
                    Op::Dec => {
                        unroll16!(self, dec_at, b);
                    }
                }
            }
            for blk in rest {
                self.step(op, blk);
            }
        }
    }

    /// `Diffuse(x0, x1)`: 16 x (`Update(x0)`, `Update(x1)`), 32 updates, offset-neutral.
    #[inline(always)]
    unsafe fn diffuse(&mut self, x0: B, x1: B) {
        unsafe {
            self.realign();
            for _ in 0..2 {
                self.update_at(0, x0);
                self.update_at(1, x1);
                self.update_at(2, x0);
                self.update_at(3, x1);
                self.update_at(4, x0);
                self.update_at(5, x1);
                self.update_at(6, x0);
                self.update_at(7, x1);
                self.update_at(8, x0);
                self.update_at(9, x1);
                self.update_at(10, x0);
                self.update_at(11, x1);
                self.update_at(12, x0);
                self.update_at(13, x1);
                self.update_at(14, x0);
                self.update_at(15, x1);
            }
        }
    }

    /// `Init(key, nonce)`.
    #[inline(always)]
    unsafe fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        unsafe {
            let (kh, _) = key.as_chunks::<16>();
            let k0 = B::load(&kh[0]);
            let k1 = B::load(&kh[1]);
            let n = B::load(nonce);
            let c0 = B::load(&C0);
            let c1 = B::load(&C1);
            let z = B::zero();
            let mut st = State {
                s: [
                    c0,
                    k0,
                    c0,
                    n,
                    z,
                    k0,
                    z,
                    c1,
                    k1,
                    z,
                    n.xor(k1),
                    c0,
                    c1,
                    k1,
                    z,
                    c0.xor(c1),
                ],
                off: 0,
            };
            st.diffuse(k0, k1);
            st
        }
    }

    /// `DecPartial(cn)` in place, `tail.len() < 16`.
    #[inline(always)]
    unsafe fn dec_partial(&mut self, tail: &mut [u8]) {
        unsafe {
            let n = tail.len();
            let off = self.off;
            let mut pad = [0u8; 16];
            pad[..n].copy_from_slice(tail);
            let s = &self.s;
            // ks = AESL(S0 ^ S1) ^ ZeroPad(cn) ^ S9; ci = cn || Tail(ks, 128 - |cn|).
            let ks = B::xaesl_x(
                s[ix(off, 0)],
                s[ix(off, 1)],
                B::load(&pad).xor(s[ix(off, 9)]),
            )
            .store();
            pad[n..].copy_from_slice(&ks[n..]);
            self.step(Op::Dec, &mut pad);
            tail.copy_from_slice(&pad[..n]);
        }
    }

    /// `Finalize(ad_len_bits, msg_len_bits)`.
    #[inline(always)]
    unsafe fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 16] {
        unsafe {
            let mut lens = [0u8; 16];
            lens[..8].copy_from_slice(&(ad_len as u64).wrapping_mul(8).to_le_bytes());
            lens[8..].copy_from_slice(&(msg_len as u64).wrapping_mul(8).to_le_bytes());
            let t = B::load(&lens);
            self.diffuse(t, t);
            let mut acc = self.s[0];
            for b in &self.s[1..] {
                acc = acc.xor(*b);
            }
            acc.store()
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

#[derive(Clone, Copy)]
enum Op {
    Absorb,
    Enc,
    Dec,
}

#[inline(always)]
unsafe fn absorb_ad<B: Block>(st: &mut State<B>, ad: &[u8]) {
    unsafe {
        let (blocks, rem) = ad.as_chunks::<16>();
        // Absorb reads its input; copy whole blocks through a scratch batch so the
        // block driver can take `&mut`.
        let mut scratch = [[0u8; 16]; 16];
        for group in blocks.chunks(16) {
            let n = group.len();
            scratch[..n].copy_from_slice(group);
            st.blocks(Op::Absorb, &mut scratch[..n]);
        }
        if !rem.is_empty() {
            let mut pad = [0u8; 16];
            pad[..rem.len()].copy_from_slice(rem);
            st.step(Op::Absorb, &mut pad);
        }
    }
}

#[inline(always)]
unsafe fn seal<B: Block>(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    unsafe {
        let mut st = State::<B>::new(key, nonce);
        absorb_ad(&mut st, ad);
        let msg_len = buf.len();
        let (blocks, rem) = buf.as_chunks_mut::<16>();
        st.blocks(Op::Enc, blocks);
        if !rem.is_empty() {
            let n = rem.len();
            let mut pad = [0u8; 16];
            pad[..n].copy_from_slice(rem);
            st.step(Op::Enc, &mut pad);
            rem.copy_from_slice(&pad[..n]);
        }
        let tag = st.finalize(ad.len(), msg_len);
        st.wipe();
        tag
    }
}

#[inline(always)]
unsafe fn open<B: Block>(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    unsafe {
        let mut st = State::<B>::new(key, nonce);
        absorb_ad(&mut st, ad);
        let msg_len = buf.len();
        let (blocks, rem) = buf.as_chunks_mut::<16>();
        st.blocks(Op::Dec, blocks);
        if !rem.is_empty() {
            st.dec_partial(rem);
        }
        let tag = st.finalize(ad.len(), msg_len);
        st.wipe();
        tag
    }
}

#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "aes,sse2")]
unsafe fn seal_aesni(k: &[u8; 32], n: &[u8; 16], ad: &[u8], b: &mut [u8]) -> [u8; 16] {
    unsafe { seal::<lib_q_intrinsics::aes_round::aesni::Ni>(k, n, ad, b) }
}

#[cfg(all(
    feature = "simd-aesni",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[target_feature(enable = "aes,sse2")]
unsafe fn open_aesni(k: &[u8; 32], n: &[u8; 16], ad: &[u8], b: &mut [u8]) -> [u8; 16] {
    unsafe { open::<lib_q_intrinsics::aes_round::aesni::Ni>(k, n, ad, b) }
}

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn seal_neon(k: &[u8; 32], n: &[u8; 16], ad: &[u8], b: &mut [u8]) -> [u8; 16] {
    unsafe { seal::<lib_q_intrinsics::aes_round::neon::Neon>(k, n, ad, b) }
}

#[cfg(all(feature = "simd-neon", target_arch = "aarch64"))]
#[target_feature(enable = "aes")]
unsafe fn open_neon(k: &[u8; 32], n: &[u8; 16], ad: &[u8], b: &mut [u8]) -> [u8; 16] {
    unsafe { open::<lib_q_intrinsics::aes_round::neon::Neon>(k, n, ad, b) }
}

/// Encrypt in place on the fastest available backend; returns the tag.
pub(crate) fn seal_dispatch(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    dispatch!(
        aesni => seal_aesni(key, nonce, ad, buf),
        neon => seal_neon(key, nonce, ad, buf),
        // SAFETY: the software backend has no CPU-feature requirements.
        soft => unsafe { seal::<Soft>(key, nonce, ad, buf) },
    )
}

/// Decrypt in place on the fastest available backend; returns the expected tag.
pub(crate) fn open_dispatch(
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    dispatch!(
        aesni => open_aesni(key, nonce, ad, buf),
        neon => open_neon(key, nonce, ad, buf),
        // SAFETY: the software backend has no CPU-feature requirements.
        soft => unsafe { open::<Soft>(key, nonce, ad, buf) },
    )
}

/// Portable-backend seal, for cross-backend equivalence tests.
pub(crate) fn seal_soft(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    // SAFETY: the software backend has no CPU-feature requirements.
    unsafe { seal::<Soft>(key, nonce, ad, buf) }
}

/// Portable-backend open, for cross-backend equivalence tests.
pub(crate) fn open_soft(key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    // SAFETY: the software backend has no CPU-feature requirements.
    unsafe { open::<Soft>(key, nonce, ad, buf) }
}
