//! Coefficient (`Poly`) vs NTT (`NttPoly`) newtypes.

use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

use crate::coeff::{
    COEFFICIENTS_IN_SIMD_UNIT,
    Coefficients,
    FieldElement,
    SIMD_UNITS_IN_RING_ELEMENT,
};
use crate::constants::{
    COEFFICIENTS_IN_RING_ELEMENT,
    FIELD_MODULUS,
};
use crate::field::{
    add_coeffs,
    reduce_element,
    reduce_poly_simd,
    subtract_coeffs,
};
use crate::ntt::{
    intt_montgomery,
    ntt_forward_simd,
    ntt_multiply_montgomery,
};

/// Polynomial in the time (coefficient) domain, canonical representatives mod `q`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct Poly {
    /// Coefficients `c[0] + c[1] X + … + c[255] X^{255}`.
    pub coeffs: [FieldElement; COEFFICIENTS_IN_RING_ELEMENT],
}

impl Poly {
    /// Zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            coeffs: [0; COEFFICIENTS_IN_RING_ELEMENT],
        }
    }

    /// Construct from canonical coefficients (already reduced mod `q` is recommended).
    #[must_use]
    pub const fn from_coeffs(coeffs: [FieldElement; COEFFICIENTS_IN_RING_ELEMENT]) -> Self {
        Self { coeffs }
    }

    /// Coefficient-wise addition mod `q` (Barrett reduction).
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..COEFFICIENTS_IN_RING_ELEMENT {
            self.coeffs[i] = reduce_element(self.coeffs[i] + rhs.coeffs[i]);
        }
    }

    /// Coefficient-wise subtraction mod `q`.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..COEFFICIENTS_IN_RING_ELEMENT {
            self.coeffs[i] = reduce_element(self.coeffs[i] - rhs.coeffs[i]);
        }
    }

    /// Multiply every coefficient by a small integer, then reduce mod `q`.
    pub fn scalar_mul_assign(&mut self, k: i32) {
        for c in &mut self.coeffs {
            *c = reduce_element((*c as i64 * k as i64) as i32);
        }
    }

    /// Negacyclic convolution mod `(X^256 + 1)` via schoolbook \(O(n^2)\) (test / reference).
    #[must_use]
    pub fn mul_negacyclic(&self, rhs: &Self) -> Self {
        let mut acc = [0i64; COEFFICIENTS_IN_RING_ELEMENT];
        let q = FIELD_MODULUS as i64;
        for i in 0..COEFFICIENTS_IN_RING_ELEMENT {
            for j in 0..COEFFICIENTS_IN_RING_ELEMENT {
                let k = i + j;
                let prod = (self.coeffs[i] as i64).wrapping_mul(rhs.coeffs[j] as i64);
                if k < COEFFICIENTS_IN_RING_ELEMENT {
                    acc[k] += prod;
                } else {
                    let idx = k - COEFFICIENTS_IN_RING_ELEMENT;
                    acc[idx] -= prod;
                }
            }
        }
        let mut out = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for (o, a) in out.iter_mut().zip(acc) {
            let mut r = a % q;
            if r < 0 {
                r += q;
            }
            *o = reduce_element(r as i32);
        }
        Self { coeffs: out }
    }

    /// Infinity norm on absolute representatives in \([-q/2, q/2]\)-style range.
    #[must_use]
    pub fn infinity_norm(&self) -> i32 {
        let half = FIELD_MODULUS / 2;
        let mut m = 0i32;
        for &c in &self.coeffs {
            let v = if c > half { c - FIELD_MODULUS } else { c };
            m = m.max(v.abs());
        }
        m
    }

    /// SIMD lane layout (ML-DSA coefficient order).
    #[must_use]
    pub fn to_simd(&self) -> [Coefficients; SIMD_UNITS_IN_RING_ELEMENT] {
        let mut s = [Coefficients::default(); SIMD_UNITS_IN_RING_ELEMENT];
        for (i, lane) in s.iter_mut().enumerate() {
            let base = i * COEFFICIENTS_IN_SIMD_UNIT;
            lane.values
                .copy_from_slice(&self.coeffs[base..base + COEFFICIENTS_IN_SIMD_UNIT]);
        }
        s
    }

    fn from_simd(simd: &[Coefficients; SIMD_UNITS_IN_RING_ELEMENT]) -> Self {
        let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for (i, lane) in simd.iter().enumerate() {
            let base = i * COEFFICIENTS_IN_SIMD_UNIT;
            coeffs[base..base + COEFFICIENTS_IN_SIMD_UNIT].copy_from_slice(&lane.values);
        }
        Self { coeffs }
    }

    /// Map to the NTT/Montgomery SIMD representation used by ML-DSA.
    #[must_use]
    pub fn to_ntt(&self) -> NttPoly {
        let mut simd = self.to_simd();
        ntt_forward_simd(&mut simd);
        NttPoly { simd }
    }
}

/// Polynomial in the NTT domain (Montgomery-lane representation).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NttPoly {
    pub(crate) simd: [Coefficients; SIMD_UNITS_IN_RING_ELEMENT],
}

impl NttPoly {
    /// Zero polynomial in NTT form.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            simd: [Coefficients::default(); SIMD_UNITS_IN_RING_ELEMENT],
        }
    }

    /// Coefficients in SIMD lane order (Montgomery NTT domain) without inverse transform.
    #[must_use]
    pub fn packed_ntt_coefficients(&self) -> [FieldElement; COEFFICIENTS_IN_RING_ELEMENT] {
        let mut c = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        for i in 0..SIMD_UNITS_IN_RING_ELEMENT {
            let base = i * COEFFICIENTS_IN_SIMD_UNIT;
            c[base..base + COEFFICIENTS_IN_SIMD_UNIT].copy_from_slice(&self.simd[i].values);
        }
        c
    }

    /// Borrow the internal SIMD lanes (read-only).
    #[must_use]
    pub fn as_simd(&self) -> &[Coefficients; SIMD_UNITS_IN_RING_ELEMENT] {
        &self.simd
    }

    /// Mutable SIMD lanes (expert use).
    pub fn as_simd_mut(&mut self) -> &mut [Coefficients; SIMD_UNITS_IN_RING_ELEMENT] {
        &mut self.simd
    }

    /// Pointwise Montgomery multiply `self *= rhs` in the NTT domain.
    pub fn pointwise_mul_assign(&mut self, rhs: &Self) {
        for i in 0..SIMD_UNITS_IN_RING_ELEMENT {
            ntt_multiply_montgomery(&mut self.simd[i], &rhs.simd[i]);
        }
    }

    /// Inverse NTT into coefficient domain with canonical reduction.
    #[must_use]
    pub fn to_poly(mut self) -> Poly {
        intt_montgomery(&mut self.simd);
        reduce_poly_simd(&mut self.simd);
        Poly::from_simd(&self.simd)
    }

    /// Add two NTT polynomials lane-wise (no modular reduction between adds; use before INTT as in ML-DSA accumulators).
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..SIMD_UNITS_IN_RING_ELEMENT {
            add_coeffs(&mut self.simd[i], &rhs.simd[i]);
        }
    }

    /// Subtract lane-wise.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..SIMD_UNITS_IN_RING_ELEMENT {
            subtract_coeffs(&mut self.simd[i], &rhs.simd[i]);
        }
    }
}

/// Fill SIMD layout from the first 256 coefficients of `buf` (ML-DSA `from_i32_array` order).
#[must_use]
pub fn simd_from_i256(
    buf: &[i32; COEFFICIENTS_IN_RING_ELEMENT],
) -> [Coefficients; SIMD_UNITS_IN_RING_ELEMENT] {
    Poly::from_coeffs(*buf).to_simd()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_step(state: &mut u64) -> u32 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (*state >> 32) as u32
    }

    fn small_poly(state: &mut u64, bound: i32) -> Poly {
        let mut coeffs = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        let width = (2 * bound + 1) as u32;
        for c in &mut coeffs {
            let v = (lcg_step(state) % width) as i32;
            *c = v - bound;
        }
        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn ntt_inverse_has_expected_linear_scale() {
        let mut one = [0i32; COEFFICIENTS_IN_RING_ELEMENT];
        one[0] = 1;
        let scale = Poly::from_coeffs(one).to_ntt().to_poly().coeffs[0];

        let mut st = 0xC0DEC0DE_u64;
        for _ in 0..16 {
            let p = small_poly(&mut st, 8);
            let back = p.clone().to_ntt().to_poly();
            for (orig, got) in p.coeffs.iter().zip(back.coeffs.iter()) {
                let expected = reduce_element((*orig as i64 * scale as i64) as i32);
                assert_eq!(expected, *got);
            }
        }
    }

    #[test]
    fn ntt_pointwise_matches_schoolbook_for_small_coeffs() {
        let mut st = 0xDEADBEEF_u64;
        for _ in 0..4 {
            let a = small_poly(&mut st, 8);
            let b = small_poly(&mut st, 8);
            let schoolbook = a.mul_negacyclic(&b);

            let mut ntt = a.to_ntt();
            let b_ntt = b.to_ntt();
            ntt.pointwise_mul_assign(&b_ntt);
            let back = ntt.to_poly();

            assert_eq!(schoolbook, back);
        }
    }
}
