//! Stable-Rust AVX-512 batched Keccak-p\[1600\] over **eight** independent states.
//!
//! This is the 8-wide sibling of [`crate::x86_simd`] (AVX2, ×4): eight independent
//! Keccak states are packed into the eight 64-bit lanes of an AVX-512 `__m512i`,
//! the XKCP `KeccakP1600times8` idea. AVX-512 is a markedly better fit for Keccak
//! than AVX2:
//!
//! * **Native 64-bit rotate** (`_mm512_rolv_epi64`) — no shift/shift/or dance.
//! * **One-instruction Chi** via `_mm512_ternarylogic_epi64`: the Keccak χ step
//!   `a ^ (!b & c)` is a single ternary-logic op (immediate `0xD2`, derived below).
//! * **32 ZMM registers** (2048 B) hold the whole 25-lane × 64 B = 1600 B state, so
//!   far less spilling than AVX2 (25 × 32 B = 800 B vs 512 B of YMM).
//!
//! Like [`crate::x86_simd`], the round function lives **inside** a
//! `#[target_feature(enable = "avx512f")]` function so the whole permutation is
//! emitted as AVX-512 and stays in vector registers (the attribute does not
//! propagate into a non-inlined generic callee — see the note in `x86_simd`).
//!
//! ## Hardware-validation note
//! The surrounding dispatch and the ×8 framing are exercised on any host through
//! the scalar fallback, and [`p1600x8`](crate::p1600x8)'s equivalence test compares
//! the result against eight scalar `p1600` calls. On a host **without** AVX-512 that
//! test runs the fallback; on AVX-512 hardware (or a CI runner) the *same* test
//! drives the real intrinsic path. Validate on AVX-512 hardware before relying on it.

use core::arch::x86_64::{
    __m512i,
    _mm512_and_si512,
    _mm512_cmpeq_epi64_mask,
    _mm512_rolv_epi64,
    _mm512_set_epi64,
    _mm512_set1_epi64,
    _mm512_setzero_si512,
    _mm512_storeu_si512,
    _mm512_ternarylogic_epi64,
    _mm512_xor_si512,
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

/// Fully unroll a 5-trip loop with a compile-time index (see `x86_simd::u5`).
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

/// Eight 64-bit Keccak lanes packed into one AVX-512 register — lane `k` holds the
/// corresponding lane of independent state `k`.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub(crate) struct U64x8(__m512i);

impl U64x8 {
    /// Extract the eight lanes as a plain array (lane `k` → `out[k]`).
    #[inline(always)]
    fn to_array(self) -> [u64; 8] {
        let mut out = [0u64; 8];
        // SAFETY: `out` is 8×u64 = 64 bytes, exactly one __m512i; `storeu` is unaligned.
        unsafe {
            _mm512_storeu_si512(out.as_mut_ptr().cast::<__m512i>(), self.0);
        }
        out
    }

    /// Keccak χ for one row: `a ^ (!b & c)`, as a single AVX-512 ternary-logic op.
    ///
    /// The immediate `0xD2` is the truth table of `f(a,b,c) = a ^ (!b & c)` where the
    /// lookup index is `(a<<2)|(b<<1)|c` (Intel's convention: `a`=bit2, `b`=bit1, `c`=bit0):
    /// `idx 0..7 → 0,1,0,0,1,0,1,1`, i.e. bits `0b1101_0010 = 0xD2`.
    #[inline(always)]
    fn chi(a: Self, b: Self, c: Self) -> Self {
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_ternarylogic_epi64::<0xD2>(a.0, b.0, c.0) })
    }
}

impl Default for U64x8 {
    #[inline(always)]
    fn default() -> Self {
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_setzero_si512() })
    }
}

impl PartialEq for U64x8 {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: reached only from the AVX-512-enabled entry point. The mask has a
        // set bit per equal lane; all eight equal ⇒ `0xFF`.
        unsafe { _mm512_cmpeq_epi64_mask(self.0, other.0) == 0xFF }
    }
}

impl fmt::Debug for U64x8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.to_array();
        write!(f, "U64x8({a:#018x?})")
    }
}

impl BitAnd for U64x8 {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_and_si512(self.0, rhs.0) })
    }
}

impl BitAndAssign for U64x8 {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitXor for U64x8 {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_xor_si512(self.0, rhs.0) })
    }
}

impl BitXorAssign for U64x8 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Not for U64x8 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_xor_si512(self.0, _mm512_set1_epi64(-1)) })
    }
}

impl LaneSize for U64x8 {
    const KECCAK_F_ROUND_COUNT: usize = 24;

    #[inline(always)]
    fn truncate_rc(rc: u64) -> Self {
        // The same round constant is broadcast to all eight independent states.
        // SAFETY: reached only from the AVX-512-enabled entry point.
        Self(unsafe { _mm512_set1_epi64(rc as i64) })
    }

    #[inline(always)]
    fn rotate_left(self, n: u32) -> Self {
        // AVX-512 has a native per-lane variable rotate; broadcast the (small, 1..=63)
        // count to all lanes. SAFETY: reached only from the AVX-512-enabled entry point.
        unsafe { Self(_mm512_rolv_epi64(self.0, _mm512_set1_epi64(i64::from(n)))) }
    }
}

/// Keccak-p\[1600, `round_count`\] over eight lanes, structurally identical to the
/// scalar [`crate::keccak_p`] but kept inside an AVX-512 `#[target_feature]` function
/// (see the module note on why this is not a call to the generic `keccak_p::<U64x8>`).
#[target_feature(enable = "avx512f")]
fn keccak_p_u64x8(state: &mut [U64x8; PLEN], round_count: usize) {
    let round_consts = &RC[(24 - round_count)..24];

    for &rc in round_consts {
        let mut array = [U64x8::default(); 5];

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

        // Chi — `a ^ (!b & c)` per row as a single ternary-logic op.
        u5!(y_step, {
            let y = 5 * y_step;
            array.copy_from_slice(&state[y..][..5]);
            u5!(x, {
                state[y + x] = U64x8::chi(array[x], array[(x + 1) % 5], array[(x + 2) % 5]);
            });
        });

        // Iota
        state[0] ^= U64x8::truncate_rc(rc);
    }
}

/// Apply Keccak-p\[1600, `round_count`\] to eight independent states at once using AVX-512.
///
/// # Safety
/// The caller must have verified that the `avx512f` target feature is available at
/// runtime (e.g. via `std::arch::is_x86_feature_detected!("avx512f")`).
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn p1600x8_avx512(states: &mut [[u64; PLEN]; 8], round_count: usize) {
    debug_assert!(round_count <= 24);

    // Transpose: lane register `i` gathers lane `i` from each of the eight states.
    let mut lanes = [U64x8::default(); PLEN];
    for (i, lane) in lanes.iter_mut().enumerate() {
        *lane = U64x8(_mm512_set_epi64(
            states[7][i] as i64,
            states[6][i] as i64,
            states[5][i] as i64,
            states[4][i] as i64,
            states[3][i] as i64,
            states[2][i] as i64,
            states[1][i] as i64,
            states[0][i] as i64,
        ));
    }

    keccak_p_u64x8(&mut lanes, round_count);

    // Transpose back.
    for (i, lane) in lanes.iter().enumerate() {
        let a = lane.to_array();
        for (s, &v) in states.iter_mut().zip(a.iter()) {
            s[i] = v;
        }
    }
}
