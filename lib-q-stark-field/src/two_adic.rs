//! Validation for two-adic subgroup orders used by FFT and coset LDE.
//!
//! Radix-2 algorithms require a subgroup of order `2^log_n` in the field's multiplicative
//! group. That is only possible when `log_n <= F::TWO_ADICITY`. Calling
//! [`TwoAdicField::two_adic_generator`] with larger `bits` is undefined and must not be
//! relied on in release builds.

use lib_q_stark_util::log2_strict_usize;

use crate::TwoAdicField;

/// Panics if `bits > F::TWO_ADICITY`.
///
/// Call before [`TwoAdicField::two_adic_generator`] or any radix-2 transform of subgroup
/// order `2^bits`.
#[inline]
pub fn assert_two_adic_bits<F: TwoAdicField>(bits: usize) {
    if bits > F::TWO_ADICITY {
        panic!(
            "two-adic order 2^{bits} exceeds {}::TWO_ADICITY = {}",
            core::any::type_name::<F>(),
            F::TWO_ADICITY,
        );
    }
}

/// Panics if `height` is not a power of two or `log2(height) > F::TWO_ADICITY`.
#[inline]
pub fn assert_two_adic_fft_height<F: TwoAdicField>(height: usize) {
    assert_two_adic_bits::<F>(log2_strict_usize(height));
}

/// Panics if coset LDE would need a subgroup larger than the field supports.
///
/// Coset LDE with blowup `2^added_bits` evaluates on a subgroup of order
/// `height << added_bits`.
#[inline]
pub fn assert_two_adic_coset_lde<F: TwoAdicField>(height: usize, added_bits: usize) {
    let log_h = log2_strict_usize(height);
    let log_order = log_h
        .checked_add(added_bits)
        .expect("coset LDE log order overflow");
    assert_two_adic_bits::<F>(log_order);
}
