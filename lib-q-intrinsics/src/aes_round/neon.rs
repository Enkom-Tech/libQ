//! ARMv8 (aarch64) AES backend.
//!
//! ARM splits the AES round differently from x86: `AESE(x, k)` computes
//! `ShiftRows(SubBytes(x ^ k))` and `AESMC` computes `MixColumns`. So
//!
//! - `AESRound(x, rk) = AESMC(AESE(x, 0)) ^ rk`, and
//! - `AESL(x ^ y) = AESMC(AESE(x, y))`, which saves an XOR on HiAE's
//!   `AESL(S0 ^ S1)` (draft-pham-cfrg-hiae, Section 7.2.1).
//!
//! `AESE`/`AESMC` run in constant time. Methods are reached only through the
//! `#[target_feature(enable = "aes")]` entry points after runtime detection.

use core::arch::aarch64::*;

use super::AesBlock;

/// ARMv8 AES 128-bit block.
#[derive(Clone, Copy, Debug)]
pub struct Neon(uint8x16_t);

impl AesBlock for Neon {
    const BITSLICED: bool = false;

    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> Self {
        unsafe { Neon(vld1q_u8(b.as_ptr())) }
    }

    #[inline(always)]
    unsafe fn store(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) };
        out
    }

    #[inline(always)]
    unsafe fn zero() -> Self {
        unsafe { Neon(vdupq_n_u8(0)) }
    }

    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        unsafe { Neon(veorq_u8(self.0, o.0)) }
    }

    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        unsafe { Neon(vandq_u8(self.0, o.0)) }
    }

    #[inline(always)]
    unsafe fn round(self, rk: Self) -> Self {
        unsafe { Neon(veorq_u8(vaesmcq_u8(vaeseq_u8(self.0, vdupq_n_u8(0))), rk.0)) }
    }

    #[inline(always)]
    unsafe fn xaesl_x(x: Self, y: Self, z: Self) -> Self {
        unsafe { Neon(veorq_u8(vaesmcq_u8(vaeseq_u8(x.0, y.0)), z.0)) }
    }
}
