//! NTT wrappers over the generated portable butterflies.

use crate::coeff::{
    Coefficients,
    SIMD_UNITS_IN_RING_ELEMENT,
};
use crate::field::montgomery_multiply_coeffs;
use crate::generated_invntt::invert_ntt_montgomery;
use crate::generated_ntt::ntt_forward as ntt_forward_generated;

/// Forward NTT (Montgomery pipeline) in the ML-DSA SIMD layout.
#[inline]
pub fn ntt_forward_simd(re: &mut [Coefficients; SIMD_UNITS_IN_RING_ELEMENT]) {
    ntt_forward_generated(re);
}

/// Inverse NTT including final Montgomery scaling (`41_978` per coefficient).
#[inline]
pub fn intt_montgomery(re: &mut [Coefficients; SIMD_UNITS_IN_RING_ELEMENT]) {
    invert_ntt_montgomery(re);
}

/// Pointwise multiply in the NTT domain (Montgomery reduction per lane).
#[inline]
pub fn ntt_multiply_montgomery(lhs: &mut Coefficients, rhs: &Coefficients) {
    montgomery_multiply_coeffs(lhs, rhs);
}
