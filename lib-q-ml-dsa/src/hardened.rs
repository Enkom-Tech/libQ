//! Side-channel hardening helpers (Cargo feature `hardened`).
//!
//! On signing entry, the secret key polynomials (`s1`, `s2`, `t0`) in Montgomery NTT form are split
//! into two additive shares per coefficient modulo `FIELD_MODULUS`:
//! `s_hat[i] = s_hat_a[i] + s_hat_b[i] (mod q)`.
//!
//! Shares are derived from a SHAKE256 stream keyed by `SEED_FOR_SIGNING` and per-invocation signing
//! randomness (no OS RNG). Each coefficient of `share_b` is uniform in `Z_q` (up to negligible
//! modular bias from `u32 % q`; see [`next_mod_field_coeff`]). Both shares are Barrett-reduced to
//! the same centered representative range as the rest of the portable pipeline before SIMD packing.
//!
//! The signing loop in [`crate::ml_dsa_generic`] multiplies each share by the challenge and sums
//! linearly, so the combined value matches the single-share path (NIST KATs unchanged).

#![cfg(feature = "hardened")]

use crate::constants::FIELD_MODULUS;
use crate::hash_functions::shake256::Xof;
use crate::polynomial::PolynomialRingElement;
use crate::simd::traits::{
    COEFFICIENTS_IN_SIMD_UNIT,
    Operations,
    SIMD_UNITS_IN_RING_ELEMENT,
};

const SPLIT_DOMAIN: &[u8] = b"lib-q-ml-dsa/hardened-sk-split-v1";

/// Sample a field element in `[0, q - 1]` from four XOF bytes via `v % q`.
///
/// **Bias:** `u32` is not divisible by `q`, so residues in `[0, (2^32 mod q) - 1]` appear once more
/// than those above; relative bias is `(2^32 mod q) / 2^32 ≈ 5.1e-4`, negligible for first-order
/// masking compared to 2⁻¹²⁸ key material.
#[inline(always)]
fn next_mod_field_coeff(xof: &mut impl Xof, buf: &mut [u8; 136], off: &mut usize) -> i32 {
    if *off + 4 > buf.len() {
        xof.squeeze(buf);
        *off = 0;
    }
    let chunk: [u8; 4] = buf[*off..*off + 4].try_into().expect("length checked");
    *off += 4;
    let v = u32::from_le_bytes(chunk);
    (v % FIELD_MODULUS as u32) as i32
}

/// Barrett-style coefficient reduction (matches portable `reduce_element` semantics).
///
/// Input must satisfy the same range as `reduce_element` in the SIMD path (`|fe| <= 2^31 - q/2`).
/// Output is congruent to `fe (mod q)` in the centered representative range used after `ntt::reduce`.
#[inline(always)]
fn reduce_coeff(fe: i32) -> i32 {
    let quotient = (fe + (1 << 22)) >> 23;
    fe - quotient * FIELD_MODULUS
}

/// Split `original` into `(share_a, share_b)` with `share_a[i] + share_b[i] ≡ original[i] (mod q)`.
fn split_polynomial_additive<S: Operations>(
    original: &mut PolynomialRingElement<S>,
    share_b: &mut PolynomialRingElement<S>,
    xof: &mut impl Xof,
    buf: &mut [u8; 136],
    off: &mut usize,
) {
    crate::ntt::reduce::<S>(original);

    let mut orig_coeffs = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    let mut b_coeffs = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
    for unit_idx in 0..SIMD_UNITS_IN_RING_ELEMENT {
        S::to_coefficient_array(&original.simd_units[unit_idx], &mut orig_coeffs);
        for j in 0..COEFFICIENTS_IN_SIMD_UNIT {
            let r = next_mod_field_coeff(xof, buf, off);
            b_coeffs[j] = reduce_coeff(r);
            orig_coeffs[j] = reduce_coeff(orig_coeffs[j] - r);
        }
        S::from_coefficient_array(&orig_coeffs, &mut original.simd_units[unit_idx]);
        S::from_coefficient_array(&b_coeffs, &mut share_b.simd_units[unit_idx]);
    }
}

/// Wire `(·_a, ·_b)` so each `·_a + ·_b` reconstructs the deserialized secret in `Z_q` per coefficient.
pub(crate) fn split_signing_key_ntt_three<S, X>(
    s1: &mut [PolynomialRingElement<S>],
    s1_b: &mut [PolynomialRingElement<S>],
    s2: &mut [PolynomialRingElement<S>],
    s2_b: &mut [PolynomialRingElement<S>],
    t0: &mut [PolynomialRingElement<S>],
    t0_b: &mut [PolynomialRingElement<S>],
    seed_for_signing: &[u8],
    signing_randomness: &[u8],
) where
    S: Operations,
    X: Xof,
{
    debug_assert_eq!(s1.len(), s1_b.len());
    debug_assert_eq!(s2.len(), s2_b.len());
    debug_assert_eq!(t0.len(), t0_b.len());

    let mut xof = X::init();
    xof.absorb(seed_for_signing);
    xof.absorb(signing_randomness);
    xof.absorb_final(SPLIT_DOMAIN);

    let mut buf = [0u8; 136];
    let mut off = buf.len();

    for i in 0..s1.len() {
        split_polynomial_additive(&mut s1[i], &mut s1_b[i], &mut xof, &mut buf, &mut off);
    }
    for i in 0..s2.len() {
        split_polynomial_additive(&mut s2[i], &mut s2_b[i], &mut xof, &mut buf, &mut off);
    }
    for i in 0..t0.len() {
        split_polynomial_additive(&mut t0[i], &mut t0_b[i], &mut xof, &mut buf, &mut off);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::COEFFICIENTS_IN_RING_ELEMENT;
    use crate::hash_functions::portable::Shake256Xof;
    use crate::simd::portable::PortableSIMDUnit;

    fn mod_q_i64(x: i64) -> i32 {
        let m = i64::from(FIELD_MODULUS);
        let r = x.rem_euclid(m);
        r as i32
    }

    #[test]
    fn next_mod_field_coeff_chi_squared_binned() {
        const BINS: usize = 256;
        const SAMPLES: usize = 400_000;
        let mut xof = Shake256Xof::init();
        xof.absorb_final(b"next_mod_field_coeff_uniformity_v1");
        let mut buf = [0u8; 136];
        let mut off = buf.len();
        let mut counts = [0usize; BINS];
        for _ in 0..SAMPLES {
            let v = next_mod_field_coeff(&mut xof, &mut buf, &mut off);
            assert!((0..FIELD_MODULUS).contains(&v));
            let bin = ((v as u64 * BINS as u64) / FIELD_MODULUS as u64) as usize;
            assert!(bin < BINS);
            counts[bin] += 1;
        }
        let expected = SAMPLES as f64 / BINS as f64;
        let mut chi_sq = 0.0_f64;
        for &c in &counts {
            let diff = c as f64 - expected;
            chi_sq += diff * diff / expected;
        }
        // df = BINS - 1 = 255; χ²_{0.999,255} ≈ 310 — use generous margin for CI noise
        assert!(
            chi_sq < 350.0,
            "chi-squared {chi_sq} suggests gross non-uniformity (bins={BINS}, n={SAMPLES})"
        );
    }

    #[test]
    fn split_polynomial_additive_recovers_mod_q() {
        let mut xof = Shake256Xof::init();
        xof.absorb_final(b"split_poly_test_v1");
        let mut buf = [0u8; 136];
        let mut off = buf.len();

        let mut a = PolynomialRingElement::<PortableSIMDUnit>::zero();
        let mut b_share = PolynomialRingElement::<PortableSIMDUnit>::zero();

        for u in 0..SIMD_UNITS_IN_RING_ELEMENT {
            let mut coeffs = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
            for c in &mut coeffs {
                *c = (u as i32 * 1000 + 17) % FIELD_MODULUS;
            }
            PortableSIMDUnit::from_coefficient_array(&coeffs, &mut a.simd_units[u]);
        }
        crate::ntt::reduce::<PortableSIMDUnit>(&mut a);

        let mut saved = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for u in 0..SIMD_UNITS_IN_RING_ELEMENT {
            let mut coeffs = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
            PortableSIMDUnit::to_coefficient_array(&a.simd_units[u], &mut coeffs);
            for j in 0..COEFFICIENTS_IN_SIMD_UNIT {
                saved[u * COEFFICIENTS_IN_SIMD_UNIT + j] = coeffs[j];
            }
        }

        split_polynomial_additive(&mut a, &mut b_share, &mut xof, &mut buf, &mut off);

        for u in 0..SIMD_UNITS_IN_RING_ELEMENT {
            let mut ca = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
            let mut cb = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
            PortableSIMDUnit::to_coefficient_array(&a.simd_units[u], &mut ca);
            PortableSIMDUnit::to_coefficient_array(&b_share.simd_units[u], &mut cb);
            for j in 0..COEFFICIENTS_IN_SIMD_UNIT {
                let idx = u * COEFFICIENTS_IN_SIMD_UNIT + j;
                let sum = mod_q_i64(i64::from(ca[j]) + i64::from(cb[j]));
                let want = mod_q_i64(i64::from(saved[idx]));
                assert_eq!(sum, want, "coeff index {idx}");
            }
        }
    }
}
