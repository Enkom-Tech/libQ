//! Side-channel hardening helpers (Cargo feature `hardened`).
//!
//! On signing entry, the secret key polynomials (`s1`, `s2`, `t0`) in Montgomery NTT form are split
//! into two additive shares per coefficient modulo `FIELD_MODULUS`:
//! `s_hat[i] = s_hat_a[i] + s_hat_b[i] (mod q)`.
//!
//! Shares are derived from a SHAKE256 stream keyed by `SEED_FOR_SIGNING`, the per-invocation FIPS
//! 204 signing randomness `rnd`, **and 32 bytes of fresh OS entropy drawn on every call**
//! ([`getrandom`], a mandatory dependency of the `hardened` feature). The fresh draw is what makes
//! the mask differ between signatures: `rnd` is the all-zero constant under FIPS 204 deterministic
//! signing, so keying on `(SEED_FOR_SIGNING, rnd)` alone regenerates the identical mask on every
//! signature and first-order masking then randomises nothing across traces (card `t_c801e460`).
//! If the OS entropy draw fails the split **refuses to run** and signing returns
//! [`crate::types::SigningError::MaskEntropyUnavailable`] — it never degrades to a static mask.
//!
//! The fresh entropy is absorbed *in addition to* the two original inputs, and the mask is summed
//! away before any output byte is produced, so the emitted signature is bit-identical to the
//! unmasked path (ACVP/NIST vectors unchanged).
//!
//! Each coefficient of `share_b` is uniform in `Z_q` (up to negligible
//! modular bias from `u32 % q`; see [`next_mod_field_coeff`]). Both shares are Barrett-reduced to
//! the same centered representative range as the rest of the portable pipeline before SIMD packing.
//!
//! The signing loop in [`crate::ml_dsa_generic`] multiplies each share by the challenge and sums
//! linearly, so the combined value matches the single-share path (NIST KATs unchanged).

#![cfg(feature = "hardened")]

use zeroize::Zeroize;

use crate::constants::FIELD_MODULUS;
use crate::hash_functions::shake256::Xof;
use crate::polynomial::PolynomialRingElement;
use crate::simd::traits::{
    COEFFICIENTS_IN_SIMD_UNIT,
    Operations,
    SIMD_UNITS_IN_RING_ELEMENT,
};

const SPLIT_DOMAIN: &[u8] = b"lib-q-ml-dsa/hardened-sk-split-v2";

/// Bytes of fresh OS entropy mixed into every mask derivation.
const FRESH_MASK_ENTROPY_SIZE: usize = 32;

/// Draw `FRESH_MASK_ENTROPY_SIZE` bytes of fresh OS entropy for this invocation's mask.
///
/// `getrandom` is a mandatory dependency of the `hardened` feature (`hardened = ["random",
/// "zeroize", "subtle", "getrandom"]`), so this is always wired. On a bare-metal target
/// `getrandom` requires a registered custom backend; that is a deliberate requirement of
/// `hardened`, not something to work around — a mask that cannot be refreshed is not a mask.
///
/// # Errors
///
/// Returns `Err(())` if the entropy source is unavailable. Callers MUST abort signing rather than
/// fall back to a key-derived-only (static) mask.
fn fresh_mask_entropy() -> Result<[u8; FRESH_MASK_ENTROPY_SIZE], ()> {
    let mut fresh = [0u8; FRESH_MASK_ENTROPY_SIZE];
    getrandom::fill(&mut fresh).map_err(|_| ())?;
    Ok(fresh)
}

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
///
/// The split stream is keyed by `seed_for_signing`, `signing_randomness` **and** a fresh 32-byte OS
/// entropy draw, so the shares differ on every call even when the first two are fixed (FIPS 204
/// deterministic signing). The reconstructed value — and therefore the emitted signature — is
/// unaffected.
///
/// # Errors
///
/// Returns `Err(())` when fresh entropy is unavailable. The caller must abort signing; there is
/// deliberately no static-mask fallback.
pub(crate) fn split_signing_key_ntt_three<S, X>(
    s1: &mut [PolynomialRingElement<S>],
    s1_b: &mut [PolynomialRingElement<S>],
    s2: &mut [PolynomialRingElement<S>],
    s2_b: &mut [PolynomialRingElement<S>],
    t0: &mut [PolynomialRingElement<S>],
    t0_b: &mut [PolynomialRingElement<S>],
    seed_for_signing: &[u8],
    signing_randomness: &[u8],
) -> Result<(), ()>
where
    S: Operations,
    X: Xof,
{
    debug_assert_eq!(s1.len(), s1_b.len());
    debug_assert_eq!(s2.len(), s2_b.len());
    debug_assert_eq!(t0.len(), t0_b.len());

    // Fresh per-invocation entropy: this, not `signing_randomness`, is what guarantees the mask
    // changes between signatures under deterministic signing. No fallback — see module docs.
    let mut fresh = fresh_mask_entropy()?;

    let mut xof = X::init();
    xof.absorb(seed_for_signing);
    xof.absorb(signing_randomness);
    xof.absorb(&fresh);
    xof.absorb_final(SPLIT_DOMAIN);

    // `hardened` implies `zeroize` (Cargo.toml), so this is always available here.
    fresh.zeroize();

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

    Ok(())
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

    /// Regression for the static-mask defect (card t_c801e460): with the SAME long-term
    /// `seed_for_signing` and the SAME FIPS 204 `rnd` (deterministic signing uses `rnd = 0^32`),
    /// two invocations must NOT produce the same additive shares. A first-order mask that is
    /// identical on every signature randomises nothing across traces.
    #[test]
    fn mask_shares_differ_across_calls_with_identical_inputs() {
        type Coeffs = [i32; COEFFICIENTS_IN_RING_ELEMENT];

        fn flatten(p: &PolynomialRingElement<PortableSIMDUnit>) -> Coeffs {
            let mut out = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
            for u in 0..SIMD_UNITS_IN_RING_ELEMENT {
                let mut c = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
                PortableSIMDUnit::to_coefficient_array(&p.simd_units[u], &mut c);
                out[u * COEFFICIENTS_IN_SIMD_UNIT..(u + 1) * COEFFICIENTS_IN_SIMD_UNIT]
                    .copy_from_slice(&c);
            }
            out
        }

        /// Returns `(share_b, share_a + share_b mod q)` for the s1 polynomial.
        fn split_once(seed: &[u8], rnd: &[u8]) -> (Coeffs, Coeffs) {
            let mut s1 = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];
            let mut s1_b = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];
            let mut s2 = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];
            let mut s2_b = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];
            let mut t0 = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];
            let mut t0_b = [PolynomialRingElement::<PortableSIMDUnit>::zero(); 1];

            // A fixed, non-zero secret so the reconstruction check is meaningful.
            for u in 0..SIMD_UNITS_IN_RING_ELEMENT {
                let mut coeffs = [0i32; COEFFICIENTS_IN_SIMD_UNIT];
                for (j, c) in coeffs.iter_mut().enumerate() {
                    *c = ((u * COEFFICIENTS_IN_SIMD_UNIT + j) as i32 * 7919) % FIELD_MODULUS;
                }
                PortableSIMDUnit::from_coefficient_array(&coeffs, &mut s1[0].simd_units[u]);
            }

            split_signing_key_ntt_three::<PortableSIMDUnit, Shake256Xof>(
                &mut s1, &mut s1_b, &mut s2, &mut s2_b, &mut t0, &mut t0_b, seed, rnd,
            )
            .expect("fresh mask entropy must be available in tests");

            let share_a = flatten(&s1[0]);
            let share_b = flatten(&s1_b[0]);
            let mut merged = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
            for i in 0..COEFFICIENTS_IN_RING_ELEMENT {
                merged[i] = mod_q_i64(i64::from(share_a[i]) + i64::from(share_b[i]));
            }
            (share_b, merged)
        }

        let seed = [0xA5u8; 32];
        // FIPS 204 deterministic signing: rnd is the all-zero constant.
        let rnd = [0u8; 32];

        let (share_b_1, merged_1) = split_once(&seed, &rnd);
        let (share_b_2, merged_2) = split_once(&seed, &rnd);

        assert_ne!(
            share_b_1, share_b_2,
            "mask shares are identical across two signings with the same key and the same rnd: \
             first-order masking provides no trace-averaging protection"
        );
        // ...while the masked value itself is unchanged, so no output byte can move.
        assert_eq!(
            merged_1, merged_2,
            "shares must re-merge to the same secret regardless of the fresh mask"
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
