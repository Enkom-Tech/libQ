//! Stable-Rust AVX2 batched Keccak-p\[1600\] over four independent states.
//!
//! A *single* Keccak-p\[1600\] state does not vectorise across SIMD lanes (see the
//! note on [`crate::x86::p1600_avx2`]), but running *four independent* states in
//! the four 64-bit lanes of an AVX2 `__m256i` is embarrassingly parallel — this
//! is the basis of XKCP's `KeccakP1600times4`.
//!
//! Unlike [`crate::simd`] (which needs nightly `core::simd`), this path works on
//! **stable** Rust by backing a [`LaneSize`] lane with `core::arch::x86_64`
//! intrinsics. The round function mirrors the scalar [`crate::keccak_p`] (same
//! `unroll5!`/`unroll24!` schedule) but lives inside an AVX2 `#[target_feature]`
//! function so the whole permutation is emitted as AVX2 and stays in vector
//! registers even when the crate is not built with `-C target-cpu=native`.

use core::arch::x86_64::{
    __m256i,
    _mm_cvtsi32_si128,
    _mm256_and_si256,
    _mm256_cmpeq_epi64,
    _mm256_movemask_epi8,
    _mm256_or_si256,
    _mm256_set_epi64x,
    _mm256_set1_epi64x,
    _mm256_setzero_si256,
    _mm256_sll_epi64,
    _mm256_srl_epi64,
    _mm256_storeu_si256,
    _mm256_xor_si256,
};
use core::fmt;
use core::ops::{
    BitAnd,
    BitAndAssign,
    BitXor,
    BitXorAssign,
    Not,
};

use crate::{
    LaneSize,
    PI,
    PLEN,
    RC,
    RHO,
};

/// Fully unroll a 5-trip loop with a compile-time index, so `array[(x+1)%5]`,
/// `PI[x]`, `RHO[x]` etc. fold to constants (no runtime table loads).
macro_rules! u5 {
    ($var:ident, $body:block) => {{
        {
            const $var: usize = 0;
            $body
        }
        {
            const $var: usize = 1;
            $body
        }
        {
            const $var: usize = 2;
            $body
        }
        {
            const $var: usize = 3;
            $body
        }
        {
            const $var: usize = 4;
            $body
        }
    }};
}

/// Fully unroll the 24-trip rho/pi loop with a compile-time index.
macro_rules! u24 {
    ($var:ident, $body:block) => {{
        {
            const $var: usize = 0;
            $body
        }
        {
            const $var: usize = 1;
            $body
        }
        {
            const $var: usize = 2;
            $body
        }
        {
            const $var: usize = 3;
            $body
        }
        {
            const $var: usize = 4;
            $body
        }
        {
            const $var: usize = 5;
            $body
        }
        {
            const $var: usize = 6;
            $body
        }
        {
            const $var: usize = 7;
            $body
        }
        {
            const $var: usize = 8;
            $body
        }
        {
            const $var: usize = 9;
            $body
        }
        {
            const $var: usize = 10;
            $body
        }
        {
            const $var: usize = 11;
            $body
        }
        {
            const $var: usize = 12;
            $body
        }
        {
            const $var: usize = 13;
            $body
        }
        {
            const $var: usize = 14;
            $body
        }
        {
            const $var: usize = 15;
            $body
        }
        {
            const $var: usize = 16;
            $body
        }
        {
            const $var: usize = 17;
            $body
        }
        {
            const $var: usize = 18;
            $body
        }
        {
            const $var: usize = 19;
            $body
        }
        {
            const $var: usize = 20;
            $body
        }
        {
            const $var: usize = 21;
            $body
        }
        {
            const $var: usize = 22;
            $body
        }
        {
            const $var: usize = 23;
            $body
        }
    }};
}

/// Four 64-bit Keccak lanes packed into one AVX2 register — lane `k` holds the
/// corresponding lane of independent state `k`.
///
/// All operations are `#[inline(always)]` so that, when reached through the
/// `#[target_feature(enable = "avx2")]` entry point [`p1600x4_avx2`], the AVX2
/// codegen context propagates into every intrinsic call.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub(crate) struct U64x4(__m256i);

impl U64x4 {
    /// Extract the four lanes as a plain array (lane `k` → `out[k]`).
    #[inline(always)]
    fn to_array(self) -> [u64; 4] {
        let mut out = [0u64; 4];
        // SAFETY: `out` is 4×u64 = 32 bytes, exactly one __m256i; `storeu` is unaligned.
        unsafe {
            _mm256_storeu_si256(out.as_mut_ptr().cast::<__m256i>(), self.0);
        }
        out
    }
}

impl Default for U64x4 {
    #[inline(always)]
    fn default() -> Self {
        // SAFETY: setzero requires only the baseline intrinsic; reached under AVX2.
        Self(unsafe { _mm256_setzero_si256() })
    }
}

impl PartialEq for U64x4 {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: reached only from the AVX2-enabled entry point.
        unsafe {
            let eq = _mm256_cmpeq_epi64(self.0, other.0);
            // Every byte is 0xFF iff all four lanes are equal.
            _mm256_movemask_epi8(eq) == -1i32
        }
    }
}

impl fmt::Debug for U64x4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.to_array();
        write!(
            f,
            "U64x4({:#018x}, {:#018x}, {:#018x}, {:#018x})",
            a[0], a[1], a[2], a[3]
        )
    }
}

impl BitAnd for U64x4 {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        // SAFETY: reached only from the AVX2-enabled entry point.
        Self(unsafe { _mm256_and_si256(self.0, rhs.0) })
    }
}

impl BitAndAssign for U64x4 {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitXor for U64x4 {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        // SAFETY: reached only from the AVX2-enabled entry point.
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl BitXorAssign for U64x4 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Not for U64x4 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        // SAFETY: reached only from the AVX2-enabled entry point.
        Self(unsafe { _mm256_xor_si256(self.0, _mm256_set1_epi64x(-1)) })
    }
}

impl LaneSize for U64x4 {
    const KECCAK_F_ROUND_COUNT: usize = 24;

    #[inline(always)]
    fn truncate_rc(rc: u64) -> Self {
        // The same round constant is broadcast to all four independent states.
        // SAFETY: reached only from the AVX2-enabled entry point.
        Self(unsafe { _mm256_set1_epi64x(rc as i64) })
    }

    #[inline(always)]
    fn rotate_left(self, n: u32) -> Self {
        // AVX2 has no 64-bit rotate. Every rotation amount used by Keccak's rho
        // and theta steps is in `1..=63`, so `64 - n` is also in `1..=63` and the
        // shift-or composition is a genuine rotate (no undefined 64-bit shift).
        debug_assert!((1..=63).contains(&n));
        // SAFETY: reached only from the AVX2-enabled entry point. `cvtsi32_si128`
        // zero-extends the 32-bit count into the low 64 bits, which is what the
        // variable-count shifts read.
        unsafe {
            let l = _mm256_sll_epi64(self.0, _mm_cvtsi32_si128(n as i32));
            let r = _mm256_srl_epi64(self.0, _mm_cvtsi32_si128((64 - n) as i32));
            Self(_mm256_or_si256(l, r))
        }
    }
}

/// Keccak-p\[1600, `round_count`\] over four lanes, structurally identical to the
/// scalar [`crate::keccak_p`] but kept **inside** an AVX2 `#[target_feature]`
/// function so every `U64x4` op (each `#[inline(always)]`) is emitted as AVX2 and
/// the 25-lane state stays in vector registers.
///
/// This is deliberately not a call to the generic `keccak_p::<U64x4>`: a
/// `#[target_feature]` attribute does not propagate into a non-inlined generic
/// callee, so routing through it would compile the body for the baseline target
/// and cross the AVX/SSE domain on every intrinsic — far slower than scalar.
#[target_feature(enable = "avx2")]
fn keccak_p_u64x4(state: &mut [U64x4; PLEN], round_count: usize) {
    let round_consts = &RC[(24 - round_count)..24];

    for &rc in round_consts {
        let mut array = [U64x4::default(); 5];

        // Theta
        u5!(x, {
            u5!(y, {
                array[x] ^= state[5 * y + x];
            });
        });
        u5!(x, {
            let t1 = array[(x + 4) % 5];
            let t2 = array[(x + 1) % 5].rotate_left(1);
            u5!(y, {
                state[5 * y + x] ^= t1 ^ t2;
            });
        });

        // Rho and pi
        let mut last = state[1];
        u24!(x, {
            array[0] = state[PI[x]];
            state[PI[x]] = last.rotate_left(RHO[x]);
            last = array[0];
        });

        // Chi
        u5!(y_step, {
            let y = 5 * y_step;
            array.copy_from_slice(&state[y..][..5]);
            u5!(x, {
                let t1 = !array[(x + 1) % 5];
                let t2 = array[(x + 2) % 5];
                state[y + x] = array[x] ^ (t1 & t2);
            });
        });

        // Iota
        state[0] ^= U64x4::truncate_rc(rc);
    }
}

/// Apply Keccak-p\[1600, `round_count`\] to four independent states at once using
/// AVX2.
///
/// # Safety
/// The caller must have verified that the `avx2` target feature is available at
/// runtime (e.g. via `std::arch::is_x86_feature_detected!("avx2")`).
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn p1600x4_avx2(states: &mut [[u64; PLEN]; 4], round_count: usize) {
    debug_assert!(round_count <= 24);

    // Transpose: lane register `i` gathers lane `i` from each of the four states.
    let mut lanes = [U64x4::default(); PLEN];
    for (i, lane) in lanes.iter_mut().enumerate() {
        *lane = U64x4(_mm256_set_epi64x(
            states[3][i] as i64,
            states[2][i] as i64,
            states[1][i] as i64,
            states[0][i] as i64,
        ));
    }

    keccak_p_u64x4(&mut lanes, round_count);

    // Transpose back.
    for (i, lane) in lanes.iter().enumerate() {
        let a = lane.to_array();
        states[0][i] = a[0];
        states[1][i] = a[1];
        states[2][i] = a[2];
        states[3][i] = a[3];
    }
}
