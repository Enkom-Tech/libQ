//! Vector helpers over `lib_q_ring::Poly`.

use alloc::vec::Vec;

use lib_q_ring::Poly;
use subtle::{
    Choice,
    ConstantTimeEq,
};

use crate::error::VerifyError;

/// Coefficient-wise addition in `R_q`.
pub fn module_add(lhs: &[Poly], rhs: &[Poly]) -> Result<Vec<Poly>, VerifyError> {
    if lhs.len() != rhs.len() {
        return Err(VerifyError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(lhs.len());
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        let mut t = a.clone();
        t.add_assign(b);
        out.push(t);
    }
    Ok(out)
}

/// Coefficient-wise subtraction.
pub fn module_sub(lhs: &[Poly], rhs: &[Poly]) -> Result<Vec<Poly>, VerifyError> {
    if lhs.len() != rhs.len() {
        return Err(VerifyError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(lhs.len());
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        let mut t = a.clone();
        t.sub_assign(b);
        out.push(t);
    }
    Ok(out)
}

/// Multiply every ring element in `v` by `c` in `R_q` (negacyclic convolution).
pub fn module_ring_mul_challenge(c: &Poly, v: &[Poly]) -> Vec<Poly> {
    v.iter().map(|p| ring_mul(c, p)).collect()
}

/// Negacyclic product `c * p` in `R_q`.
pub fn ring_mul(c: &Poly, p: &Poly) -> Poly {
    let mut cn = c.to_ntt();
    let pn = p.to_ntt();
    cn.pointwise_mul_assign(&pn);
    cn.to_poly()
}

/// Infinity norm over all coefficients in a vector of polynomials.
pub fn module_infinity_norm(v: &[Poly]) -> i32 {
    v.iter().map(Poly::infinity_norm).max().unwrap_or(0)
}

/// Constant-time lexicographic equality of serialized coefficient vectors.
pub fn polys_ct_eq(a: &[Poly], b: &[Poly]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0u8);
    }
    let mut acc = Choice::from(1u8);
    for (x, y) in a.iter().zip(b.iter()) {
        for (xc, yc) in x.coeffs.iter().zip(y.coeffs.iter()) {
            acc &= xc.ct_eq(yc);
        }
    }
    acc
}
