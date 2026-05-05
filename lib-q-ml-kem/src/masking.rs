//! Side-channel hardening helpers (feature `hardened`).
//!
//! This module implements countermeasures used on the ML-KEM decapsulation path:
//! - First-order additive sharing for the secret `s_hat` in the NTT-domain dot product with `u_hat`
//! - Multiplicative masking of both factors (`rho * s_hat` with `rho^-1 * u_hat`) before the product
//! - Constant-time CBD table lookup (avoids secret-dependent indexing into `Eta::ONES`)
//! - Fisher–Yates shuffling of the order in which K-wise NTT products are accumulated
//!
//! Re-encryption uses the same masked NTT matrix–vector and `t_hat · r_hat` products as the
//! default path, with independent masking factors per row (`ntt_matrix_vector_masked`).
//! **NTT domain blinding:** under `hardened`, [`crate::algebra::Polynomial::ntt`] and
//! [`crate::algebra::NttPolynomial::ntt_inverse`] multiply the transform I/O by a random
//! \\(r \\in \\mathbb{Z}_q^\\*\\) and \\(r^{-1}\\) (Kyber NTT is \\(\\mathbb{Z}_q\\)-linear), masking
//! intermediate butterfly values without changing the mathematical result.
//!
//! **PolyZeroTestAB (coefficient / arithmetic domain):** decapsulation combines byte-wise
//! [`ciphertexts_equal_ct`] with [`ciphertexts_equal_arithmetic_domain_ct`], which decodes `u` and
//! `v` and compares every coefficient with `subtle`. Both must agree to select `Kp` (logical
//! ciphertext equality in the ring implies both checks pass).

#![allow(clippy::explicit_iter_loop)]

use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;
use rand_core::Rng;
use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::algebra::{
    FieldElement,
    NttPolynomial,
    NttVector,
    Polynomial,
    PolynomialVector,
};
use crate::crypto::PrfOutput;
use crate::encode::Encode;
pub(crate) use crate::hardened_rng::OsRngFill;
use crate::param::{
    ArraySize,
    CbdSamplingSize,
    EncodedCiphertext,
    KemParams,
};
use crate::util::B32;

/// Constant-time lookup into `Eta::ONES` using the decoded CBD index `v`.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn cbd_table_lookup_ct<Eta: CbdSamplingSize>(v: u8) -> FieldElement {
    let mut acc = FieldElement(0);
    let max = Eta::OnesSize::USIZE as u8;
    for i in 0..max {
        let pick = v.ct_eq(&i);
        let cand = Eta::ONES[usize::from(i)].0;
        acc.0 = u16::conditional_select(&acc.0, &cand, pick);
    }
    acc
}

/// CBD sampling with constant-time table lookup (distribution matches [`Polynomial::sample_cbd`]).
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn sample_poly_cbd_ct<Eta: CbdSamplingSize>(b: &PrfOutput<Eta>) -> Polynomial {
    let vals: Polynomial = Encode::<Eta::SampleSize>::decode(b);
    Polynomial(
        vals.0
            .iter()
            .map(|val| cbd_table_lookup_ct::<Eta>(val.0 as u8))
            .collect(),
    )
}

/// First-order shared NTT-domain inner product `(s_hat · u_hat)` with multiplicative rho masking and
/// shuffled summation order. Algebraically identical to the default `Mul` impl on [`NttVector`].
pub(crate) fn ntt_vector_dot_masked<K: ArraySize, R: Rng>(
    s_hat: &NttVector<K>,
    u_hat: &NttVector<K>,
    rng: &mut R,
) -> NttPolynomial {
    let k = K::USIZE;
    debug_assert_eq!(k, s_hat.0.len());
    debug_assert_eq!(k, u_hat.0.len());
    debug_assert!(k <= 4);

    let rho = FieldElement::random_nonzero(rng);
    let rho_inv = rho
        .inv()
        .expect("nonzero rho must have an inverse mod FIELD_MODULUS");

    let mut s_masked = NttVector::<K>(Array::default());
    let mut u_masked = NttVector::<K>(Array::default());
    for i in 0..k {
        s_masked.0[i] = scale_ntt_polynomial(&s_hat.0[i], rho);
        u_masked.0[i] = scale_ntt_polynomial(&u_hat.0[i], rho_inv);
    }

    let mut s0 = NttVector::<K>(Array::default());
    let mut s1 = NttVector::<K>(Array::default());
    for i in 0..k {
        split_ntt_polynomial_share(&s_masked.0[i], rng, &mut s0.0[i], &mut s1.0[i]);
    }

    let mut perm = [0usize; 4];
    crate::hardened_rng::shuffle_indices(rng, k, &mut perm[..k]);

    let mut acc = NttPolynomial::default();
    for &idx in perm[..k].iter() {
        let t0 = &s0.0[idx] * &u_masked.0[idx];
        let t1 = &s1.0[idx] * &u_masked.0[idx];
        acc = &(&acc + &t0) + &t1;
        // First-order mask refresh on the packed accumulator would split `acc` into two NTT shares
        // and re-randomise between limb products; the public API keeps a single accumulator while
        // still randomising `s_hat` limbs and multiplication order (see module header).
    }
    acc
}

/// NTT-domain matrix–vector product `A * r_hat` with the same masking strategy as
/// [`ntt_vector_dot_masked`] applied row-wise (independent `rho` per row).
pub(crate) fn ntt_matrix_vector_masked<K: ArraySize, R: Rng>(
    matrix: &crate::algebra::NttMatrix<K>,
    r_hat: &NttVector<K>,
    rng: &mut R,
) -> NttVector<K> {
    let mut out = NttVector::<K>(Array::default());
    for i in 0..K::USIZE {
        out.0[i] = ntt_vector_dot_masked(matrix.row(i), r_hat, rng);
    }
    out
}

fn scale_ntt_polynomial(p: &NttPolynomial, s: FieldElement) -> NttPolynomial {
    NttPolynomial(p.0.iter().map(|&x| x * s).collect())
}

fn split_ntt_polynomial_share<R: Rng>(
    s: &NttPolynomial,
    rng: &mut R,
    s0: &mut NttPolynomial,
    s1: &mut NttPolynomial,
) {
    for i in 0..256 {
        let mask = random_fe(rng);
        s1.0[i] = mask;
        s0.0[i] = s.0[i] - mask;
    }
}

/// Uniform `FieldElement` (may be zero).
fn random_fe<R: Rng>(rng: &mut R) -> FieldElement {
    let mut buf = [0u8; 2];
    rng.fill_bytes(&mut buf);
    FieldElement::from_u16_reduced(u16::from_le_bytes(buf))
}

/// Constant-time equality of two ML-KEM ciphertext byte arrays.
pub(crate) fn ciphertexts_equal_ct(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let mut eq = Choice::from(1u8);
    for (&x, &y) in a.iter().zip(b.iter()) {
        eq &= x.ct_eq(&y);
    }
    eq
}

fn polynomial_ct_eq(a: &Polynomial, b: &Polynomial) -> Choice {
    let mut eq = Choice::from(1u8);
    for i in 0..256 {
        eq &= a.0[i].0.ct_eq(&b.0[i].0);
    }
    eq
}

fn polynomial_vector_ct_eq<K: ArraySize>(
    a: &PolynomialVector<K>,
    b: &PolynomialVector<K>,
) -> Choice {
    let mut eq = Choice::from(1u8);
    for i in 0..K::USIZE {
        eq &= polynomial_ct_eq(&a.0[i], &b.0[i]);
    }
    eq
}

/// Constant-time equality after `ByteDecode` of the `(u, v)` components — coefficient-wise test in
/// the ring `R_q` (the Boolean output of a PolyZero-style check in the uncompressed domain).
pub(crate) fn ciphertexts_equal_arithmetic_domain_ct<P: KemParams>(
    a: &EncodedCiphertext<P>,
    b: &EncodedCiphertext<P>,
) -> Choice {
    let (a_u, a_v) = P::split_ct(a);
    let (b_u, b_v) = P::split_ct(b);
    let ua: PolynomialVector<P::K> = Encode::<P::Du>::decode(a_u);
    let ub: PolynomialVector<P::K> = Encode::<P::Du>::decode(b_u);
    let va: Polynomial = Encode::<P::Dv>::decode(a_v);
    let vb: Polynomial = Encode::<P::Dv>::decode(b_v);
    polynomial_vector_ct_eq(&ua, &ub) & polynomial_ct_eq(&va, &vb)
}

/// Select `lhs` or `rhs` per byte using the same `Choice` (implicit rejection mux).
pub(crate) fn select_shared_key_bytes_ct(eq: Choice, lhs: &B32, rhs: &B32) -> B32 {
    let mut out = B32::default();
    for i in 0..32 {
        out[i] = u8::conditional_select(&rhs[i], &lhs[i], eq);
    }
    out
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use rand_core::{
        Infallible,
        TryRng,
    };

    use super::*;
    use crate::MlKem768Params;
    use crate::algebra::PolynomialVector;
    use crate::param::ParameterSet;
    use crate::pke::DecryptionKey;

    struct CountingRng(u64);

    impl TryRng for CountingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(self.0 as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for b in dest.iter_mut() {
                *b = self.try_next_u32()? as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn ntt_dot_masked_matches_plain() {
        let d = B32::default();
        let (dk, _ek) = DecryptionKey::<MlKem768Params>::generate(&d);
        let mut rng = CountingRng(0xDEAD_BEEF);
        let u = PolynomialVector::<<MlKem768Params as ParameterSet>::K>::sample_cbd::<
            <MlKem768Params as ParameterSet>::Eta1,
        >(&d, 0);
        let u_hat = u.ntt();

        let plain = dk.test_s_hat() * &u_hat;
        let masked = ntt_vector_dot_masked(dk.test_s_hat(), &u_hat, &mut rng);
        assert_eq!(plain, masked);
    }
}
