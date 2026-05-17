//! Montgomery multiply-accumulate and Barrett reduction (ML-DSA portable path).

use crate::coeff::{
    COEFFICIENTS_IN_SIMD_UNIT,
    Coefficients,
    FieldElement,
    SIMD_UNITS_IN_RING_ELEMENT,
};
use crate::constants::{
    FIELD_MODULUS,
    INVERSE_OF_MODULUS_MOD_MONTGOMERY_R,
    MONTGOMERY_SHIFT,
};

/// Values ≡ `x · Montgomery_R (mod q)`.
pub type FieldElementTimesMontgomeryR = i32;

#[inline(always)]
fn get_n_least_significant_bits(n: u8, value: u64) -> u64 {
    value & ((1 << n) - 1)
}

/// Montgomery reduction: map `value` (interpreted mod `2^32`) to standard representative mod `q`.
#[inline(always)]
pub fn montgomery_reduce_element(value: i64) -> FieldElementTimesMontgomeryR {
    let t = get_n_least_significant_bits(MONTGOMERY_SHIFT, value as u64) *
        INVERSE_OF_MODULUS_MOD_MONTGOMERY_R;
    let k = get_n_least_significant_bits(MONTGOMERY_SHIFT, t) as i32;
    let k_times_modulus = (k as i64) * (FIELD_MODULUS as i64);
    let c = (k_times_modulus >> MONTGOMERY_SHIFT) as i32;
    let value_high = (value >> MONTGOMERY_SHIFT) as i32;
    value_high - c
}

#[inline(always)]
pub fn montgomery_multiply_fe_by_fer(
    fe: FieldElement,
    fer: FieldElementTimesMontgomeryR,
) -> FieldElement {
    montgomery_reduce_element((fe as i64) * (fer as i64))
}

/// Pointwise Montgomery multiply: `lhs[i] = mont_red(lhs[i] * rhs[i])`.
#[inline(always)]
pub fn montgomery_multiply_coeffs(lhs: &mut Coefficients, rhs: &Coefficients) {
    for i in 0..lhs.values.len() {
        lhs.values[i] = montgomery_reduce_element((lhs.values[i] as i64) * (rhs.values[i] as i64));
    }
}

#[inline(always)]
pub fn montgomery_multiply_by_constant(simd_unit: &mut Coefficients, c: i32) {
    for i in 0..simd_unit.values.len() {
        simd_unit.values[i] = montgomery_reduce_element((simd_unit.values[i] as i64) * (c as i64));
    }
}

#[inline(always)]
pub fn reduce_element(fe: FieldElement) -> FieldElement {
    let quotient = (fe + (1 << 22)) >> 23;
    fe - (quotient * FIELD_MODULUS)
}

#[inline(always)]
pub fn add_coeffs(lhs: &mut Coefficients, rhs: &Coefficients) {
    for i in 0..lhs.values.len() {
        lhs.values[i] += rhs.values[i];
    }
}

#[inline(always)]
pub fn subtract_coeffs(lhs: &mut Coefficients, rhs: &Coefficients) {
    for i in 0..lhs.values.len() {
        lhs.values[i] -= rhs.values[i];
    }
}

/// Reduce every coefficient into `[0, q)` using Barrett-style reduction.
pub fn reduce_poly_simd(simd_units: &mut [Coefficients; SIMD_UNITS_IN_RING_ELEMENT]) {
    for unit in simd_units.iter_mut() {
        for i in 0..COEFFICIENTS_IN_SIMD_UNIT {
            unit.values[i] = reduce_element(unit.values[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_reduce_kat() {
        assert_eq!(montgomery_reduce_element(10_933_346_042_510), -1_553_279);
        assert_eq!(montgomery_reduce_element(-20_392_060_523_118), 1_331_779);
        assert_eq!(montgomery_reduce_element(13_704_140_696_092), -1_231_016);
        assert_eq!(montgomery_reduce_element(-631_922_212_176), -2_580_954);
    }

    #[test]
    fn barrett_reduce_subset_matches_mod_q() {
        let q = FIELD_MODULUS as i64;
        for x in (0..2_000_000_i64).step_by(997) {
            let reduced = reduce_element(x as i32) as i64;
            let expected = x % q;
            assert_eq!(reduced, expected);
        }
    }
}
