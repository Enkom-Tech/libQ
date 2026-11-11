//! Recursive Karatsuba GF(2)\[x\] multiplication with modular reduction \(x^N - 1\).
//!
//! Portable (architecture-independent) counterpart to
//! [`crate::simd::avx2::gf2x::avx2_vect_mul_mod_xnm1`]: both compute the same
//! `output = a * b mod (x^N - 1)` product over `GF(2)`, but this path uses no platform
//! intrinsics, so it is what every non-x86_64/no-AVX2 target — `wasm32`, `aarch64`,
//! `armv7`/`thumbv7em` (once the crate's `no_std`+`alloc` build is otherwise buildable
//! for those targets) and non-AVX2 x86_64 — gets instead of the quadratic
//! [`crate::hqc_pke::schoolbook_vect_mul_mod_xnm1`].
//!
//! # Algorithm
//!
//! Two-way (Karatsuba) recursive split on whole 64-bit words: an `n`-word operand
//! splits into a `lo_len = n / 2` word low half and a `hi_len = n - lo_len` word high
//! half. The split is word-aligned (an exact word shift, never a bit shift), giving the
//! standard three-recursive-multiply combination
//! `A*B = A_lo*B_lo + (A_lo*B_hi + A_hi*B_lo)*x^(lo_len*64) + A_hi*B_hi*x^(2*lo_len*64)`,
//! computed over `GF(2)` (so `+` is XOR) as `z0 = A_lo*B_lo`, `z2 = A_hi*B_hi`,
//! `z1 = (A_lo^A_hi)*(B_lo^B_hi) ^ z0 ^ z2`. Recursion bottoms out at
//! [`KARATSUBA_THRESHOLD_WORDS`] words into the same branch-free bit-serial schoolbook
//! technique [`crate::hqc_pke::schoolbook_vect_mul_mod_xnm1`] uses internally, just
//! producing an unreduced `2*n`-word product instead of reducing along the way; the
//! `x^N - 1` reduction is applied once, at the top level, using the identical reduction
//! step schoolbook uses on its own unreduced buffer.
//!
//! # Constant-time discipline
//!
//! Every control-flow decision that depends on the *shape* of the operands (the
//! recursive split point, the base-case threshold, every loop bound) is a function of
//! `a.len()`/`b.len()` only, i.e. the public HQC parameter set, never of the bit values
//! inside `a`/`b`, which are secret: there is no early exit and no lookup table indexed
//! by `a` or `b` anywhere in this module. The base case reuses
//! [`crate::hqc_pke::schoolbook_vect_mul_mod_xnm1`]'s own technique verbatim: for every
//! bit position, `if (ai >> bit) & 1 == 1 { !0u64 } else { 0u64 }` derives an
//! all-ones/all-zeros mask from one secret bit and combines it into the accumulator
//! uniformly via `&`/`^`, so the source has no branch whose *bodies* differ in the
//! operations performed or the memory touched. As with the reference schoolbook this
//! module mirrors, the mask derivation is written as an `if`/`else` over two compile-time
//! constants (not a hand-verified branchless select), so this file makes exactly the
//! same constant-time claim schoolbook already makes -- no stronger, no weaker -- and
//! carries the same project-wide caveat recorded in `docs/vector-operations.md`'s
//! side-channel table: cycle count is not independently audited to be branch-free at
//! the compiled-code level.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;

use crate::hqc_pke::HqcPkeError;

/// Word-count threshold below which recursion bottoms out into the bit-serial
/// schoolbook base case. Chosen so recursion overhead (allocations, XOR combination
/// passes) does not dominate at HQC's smallest per-call operand sizes; this path has
/// no target-specific specialization, so the threshold is not microarchitecture-tuned.
const KARATSUBA_THRESHOLD_WORDS: usize = 16;

/// `output = a * b mod (x^n_bits - 1)` over `GF(2)`, computed via recursive Karatsuba.
///
/// Drop-in equivalent of [`crate::hqc_pke::schoolbook_vect_mul_mod_xnm1`]: identical
/// signature and identical modular-reduction step, but a sub-quadratic dense multiply
/// (`O(n^log2(3))` word operations instead of `O(n^2)`) feeding it.
pub fn karatsuba_vect_mul_mod_xnm1(
    output: &mut [u64],
    a: &[u64],
    b: &[u64],
    vec_n_words: usize,
    n_bits: usize,
) -> Result<(), HqcPkeError> {
    debug_assert!(
        !n_bits.is_multiple_of(64),
        "karatsuba_vect_mul_mod_xnm1: N multiple of 64 not supported by this reduction"
    );
    if output.len() != vec_n_words || a.len() < vec_n_words || b.len() < vec_n_words {
        return Err(HqcPkeError::InvalidKey);
    }

    let mut unreduced = vec![0u64; 2 * vec_n_words];
    full_mul(&a[..vec_n_words], &b[..vec_n_words], &mut unreduced);

    let mask_n = n_bits & 0x3F;
    for i in 0..vec_n_words {
        let r = unreduced[i + vec_n_words - 1] >> mask_n;
        let carry = unreduced[i + vec_n_words] << (64 - mask_n);
        output[i] = unreduced[i] ^ r ^ carry;
    }
    output[vec_n_words - 1] &= (1u64 << mask_n) - 1;
    Ok(())
}

/// Full (unreduced) `GF(2)[x]` product of two equal-length word arrays:
/// `out[0..2*n] ^= a * b`, where `n = a.len() == b.len()`.
///
/// `out` MUST already be zero-filled by the caller — every call site in this module
/// allocates its scratch with `vec![0u64; _]`, which zero-fills — because this
/// function XORs its result in rather than overwriting, so recursive callers can share
/// the same accumulation code as the top-level entry point.
fn full_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert!(out.len() >= 2 * n);

    if n <= KARATSUBA_THRESHOLD_WORDS {
        schoolbook_full_mul(a, b, out);
        return;
    }

    let lo_len = n / 2;
    let hi_len = n - lo_len;
    let (a_lo, a_hi) = a.split_at(lo_len);
    let (b_lo, b_hi) = b.split_at(lo_len);

    // z0 = a_lo * b_lo
    let mut z0 = vec![0u64; 2 * lo_len];
    full_mul(a_lo, b_lo, &mut z0);

    // z2 = a_hi * b_hi
    let mut z2 = vec![0u64; 2 * hi_len];
    full_mul(a_hi, b_hi, &mut z2);

    // z1 = (a_lo ^ a_hi) * (b_lo ^ b_hi) ^ z0 ^ z2 = a_lo*b_hi ^ a_hi*b_lo
    let mut mid_a = vec![0u64; hi_len];
    mid_a[..lo_len].copy_from_slice(a_lo);
    for (m, &h) in mid_a.iter_mut().zip(a_hi) {
        *m ^= h;
    }
    let mut mid_b = vec![0u64; hi_len];
    mid_b[..lo_len].copy_from_slice(b_lo);
    for (m, &h) in mid_b.iter_mut().zip(b_hi) {
        *m ^= h;
    }
    let mut z1 = vec![0u64; 2 * hi_len];
    full_mul(&mid_a, &mid_b, &mut z1);
    for (z1w, &z0w) in z1.iter_mut().zip(z0.iter()) {
        *z1w ^= z0w;
    }
    for (z1w, &z2w) in z1.iter_mut().zip(z2.iter()) {
        *z1w ^= z2w;
    }

    // out = z0 + z1 * x^(lo_len words) + z2 * x^(2*lo_len words)
    for (o, &z) in out[..2 * lo_len].iter_mut().zip(z0.iter()) {
        *o ^= z;
    }
    for (o, &z) in out[lo_len..lo_len + 2 * hi_len].iter_mut().zip(z1.iter()) {
        *o ^= z;
    }
    for (o, &z) in out[2 * lo_len..2 * lo_len + 2 * hi_len]
        .iter_mut()
        .zip(z2.iter())
    {
        *o ^= z;
    }
}

/// Bit-serial base case: `out[0..2*n] ^= a * b` (no modular reduction), mirroring
/// [`crate::hqc_pke::schoolbook_vect_mul_mod_xnm1`]'s inner double loop exactly, minus
/// its final `mod (x^n_bits - 1)` reduction step. Same constant-time posture as that
/// function (module doc above).
fn schoolbook_full_mul(a: &[u64], b: &[u64], out: &mut [u64]) {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    debug_assert!(out.len() >= 2 * n);

    for (i, &ai) in a.iter().enumerate() {
        for bit in 0..64 {
            let mask = if (ai >> bit) & 1 == 1 { !0u64 } else { 0u64 };
            let sh = bit;
            if sh == 0 {
                for j in 0..n {
                    out[i + j] ^= b[j] & mask;
                }
            } else {
                let inv = 64 - sh;
                for j in 0..n {
                    out[i + j] ^= (b[j] << sh) & mask;
                    out[i + j + 1] ^= (b[j] >> inv) & mask;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hqc_pke::schoolbook_vect_mul_mod_xnm1;
    use crate::params::{Hqc1Params, HqcParams};

    fn assert_karatsuba_matches_schoolbook<P: HqcParams>(seeds: &[u64]) {
        let n = P::VEC_N_SIZE_64;
        let mask = (1u64 << (P::N & 0x3F)) - 1;
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        let mut s = vec![0u64; n];
        let mut k = vec![0u64; n];
        for &seed in seeds {
            for i in 0..n {
                let t = seed
                    .wrapping_add(i as u64)
                    .wrapping_mul(0xD1_B54_321_0FED_CBA9);
                a[i] = t;
                b[i] = t.rotate_left(17) ^ 0xA5A5_A5A5_A5A5_A5A5;
            }
            a[n - 1] &= mask;
            b[n - 1] &= mask;
            schoolbook_vect_mul_mod_xnm1(&mut s, &a, &b, n, P::N).unwrap();
            karatsuba_vect_mul_mod_xnm1(&mut k, &a, &b, n, P::N).unwrap();
            assert_eq!(s, k, "P={} seed={seed}", core::any::type_name::<P>());
        }
    }

    #[test]
    fn karatsuba_matches_schoolbook_hqc128() {
        assert_karatsuba_matches_schoolbook::<Hqc1Params>(&[1u64, 2, 42, 0xDEADBEEF]);
    }

    #[cfg(feature = "hqc192")]
    #[test]
    fn karatsuba_matches_schoolbook_hqc192() {
        assert_karatsuba_matches_schoolbook::<crate::params::Hqc3Params>(&[1u64, 7, 0xBEEF]);
    }

    #[cfg(feature = "hqc256")]
    #[test]
    fn karatsuba_matches_schoolbook_hqc256() {
        assert_karatsuba_matches_schoolbook::<crate::params::Hqc5Params>(&[3u64, 11, 0xFACADE]);
    }

    /// Every recursive split boundary in `full_mul` is exercised as operand size grows
    /// past each threshold crossing, so this is not limited to HQC's fixed N: it checks
    /// arbitrary word counts on both sides of `KARATSUBA_THRESHOLD_WORDS` and both
    /// parities of the low/high split.
    #[test]
    fn karatsuba_matches_schoolbook_across_recursion_boundaries() {
        for n in 1..80 {
            let mut a = vec![0u64; n];
            let mut b = vec![0u64; n];
            for i in 0..n {
                a[i] = (i as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
                b[i] = (i as u64 + 7).wrapping_mul(0xBF58476D1CE4E5B9);
            }
            // n_bits chosen not a multiple of 64, matching every real HQC parameter set.
            let n_bits = n * 64 - 1;
            let mut s = vec![0u64; n];
            let mut k = vec![0u64; n];
            schoolbook_vect_mul_mod_xnm1(&mut s, &a, &b, n, n_bits).unwrap();
            karatsuba_vect_mul_mod_xnm1(&mut k, &a, &b, n, n_bits).unwrap();
            assert_eq!(s, k, "n={n}");
        }
    }

    /// The equivalence assertion above is not vacuous: corrupting one word of a
    /// genuine Karatsuba output must make it disagree with the schoolbook oracle.
    #[test]
    fn equivalence_assert_detects_a_wrong_multiply() {
        let n = Hqc1Params::VEC_N_SIZE_64;
        let mask = (1u64 << (Hqc1Params::N & 0x3F)) - 1;
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        for i in 0..n {
            a[i] = (i as u64 + 3).wrapping_mul(0x2545F4914F6CDD1D);
            b[i] = (i as u64 + 5).wrapping_mul(0x9E3779B97F4A7C15);
        }
        a[n - 1] &= mask;
        b[n - 1] &= mask;
        let mut s = vec![0u64; n];
        let mut k = vec![0u64; n];
        schoolbook_vect_mul_mod_xnm1(&mut s, &a, &b, n, Hqc1Params::N).unwrap();
        karatsuba_vect_mul_mod_xnm1(&mut k, &a, &b, n, Hqc1Params::N).unwrap();
        assert_eq!(s, k, "sanity: must agree before corruption");
        k[0] ^= 1;
        assert_ne!(
            s, k,
            "corrupted output must disagree with the schoolbook oracle"
        );
    }
}
