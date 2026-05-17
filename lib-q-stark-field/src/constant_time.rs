//! Constant-time operations for field elements.
//!
//! This module provides constant-time implementations of common field operations
//! to prevent timing-based side-channel attacks.

use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::Field;

/// Constant-time equality comparison for field elements.
///
/// This operation takes constant time regardless of whether the values are equal,
/// preventing timing attacks that could leak information about secret values.
///
/// # Arguments
/// * `a` - First field element
/// * `b` - Second field element
///
/// # Returns
/// `true` if the elements are equal, `false` otherwise.
///
/// # Security
/// The comparison is performed in constant time to prevent timing attacks.
pub fn constant_time_eq<F: Field + ConstantTimeEq>(a: &F, b: &F) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time conditional selection.
///
/// Returns `a` if `condition` is true, `b` otherwise. The selection is performed
/// in constant time regardless of the condition value.
///
/// # Arguments
/// * `condition` - Boolean condition (true selects `a`, false selects `b`)
/// * `a` - Value to return if condition is true
/// * `b` - Value to return if condition is false
///
/// # Returns
/// `a` if condition is true, `b` otherwise.
///
/// # Security
/// The selection is performed in constant time to prevent timing attacks.
pub fn constant_time_select<F>(condition: bool, a: F, b: F) -> F
where
    F: Field + ConditionallySelectable,
{
    F::conditional_select(&a, &b, Choice::from(condition as u8))
}

/// Constant-time conditional assignment.
///
/// If `condition` is true, assigns `src` to `dst`. Otherwise, leaves `dst` unchanged.
/// The assignment is performed in constant time regardless of the condition value.
///
/// # Arguments
/// * `condition` - Boolean condition
/// * `dst` - Destination field element (modified if condition is true)
/// * `src` - Source field element (assigned to dst if condition is true)
///
/// # Security
/// The assignment is performed in constant time to prevent timing attacks.
pub fn constant_time_assign<F>(condition: bool, dst: &mut F, src: F)
where
    F: Field + ConditionallySelectable,
{
    *dst = F::conditional_select(dst, &src, Choice::from(condition as u8));
}

/// Constant-time check if a field element is zero.
///
/// Returns `true` if the element is zero, `false` otherwise.
/// The check is performed in constant time.
///
/// # Arguments
/// * `value` - Field element to check
///
/// # Returns
/// `true` if the element is zero, `false` otherwise.
///
/// # Security
/// The check is performed in constant time to prevent timing attacks.
pub fn constant_time_is_zero<F>(value: &F) -> bool
where
    F: Field + ConstantTimeEq,
{
    value.ct_eq(&F::ZERO).into()
}

/// Constant-time check if a field element is one.
///
/// Returns `true` if the element is one, `false` otherwise.
/// The check is performed in constant time.
///
/// # Arguments
/// * `value` - Field element to check
///
/// # Returns
/// `true` if the element is one, `false` otherwise.
///
/// # Security
/// The check is performed in constant time to prevent timing attacks.
pub fn constant_time_is_one<F>(value: &F) -> bool
where
    F: Field + ConstantTimeEq,
{
    value.ct_eq(&F::ONE).into()
}
