//! x86 / x86_64 AES-NI backend.
//!
//! `_mm_aesenc_si128(x, rk)` computes `MixColumns(ShiftRows(SubBytes(x))) ^ rk`,
//! which is exactly `AESRound(x, rk)`. The register byte order matches the
//! column-major order of the portable backend. `AESENC` runs in constant time.
//!
//! Methods are `#[inline(always)]` and are only reached through the
//! `#[target_feature(enable = "aes,sse2")]` entry points in the algorithm
//! crates, after runtime detection (see [`super::hardware_aes_available`]).

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::AesBlock;

/// AES-NI 128-bit block.
#[derive(Clone, Copy, Debug)]
pub struct Ni(__m128i);

impl AesBlock for Ni {
    const BITSLICED: bool = false;

    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> Self {
        unsafe { Ni(_mm_loadu_si128(b.as_ptr().cast::<__m128i>())) }
    }

    #[inline(always)]
    unsafe fn store(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), self.0) };
        out
    }

    #[inline(always)]
    unsafe fn zero() -> Self {
        unsafe { Ni(_mm_setzero_si128()) }
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        unsafe { Ni(_mm_xor_si128(self.0, o.0)) }
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        unsafe { Ni(_mm_and_si128(self.0, o.0)) }
    }

    #[inline(always)]
    unsafe fn round(self, rk: Self) -> Self {
        unsafe { Ni(_mm_aesenc_si128(self.0, rk.0)) }
    }
}
