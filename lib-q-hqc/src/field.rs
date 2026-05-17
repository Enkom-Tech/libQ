//! GF(2) Field Element Implementation for HQC
//!
//! This module provides a proper field element implementation for GF(2) operations
//! used in HQC polynomial arithmetic. This follows the same secure architecture
//! patterns as ML-KEM and ML-DSA.

use core::ops::{
    Add,
    Mul,
    Sub,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// A field element in GF(2)
///
/// In GF(2), there are only two elements: 0 and 1.
/// This is represented as a boolean for efficiency and clarity.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldElement(pub bool);

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0 = false;
    }
}

impl FieldElement {
    /// The zero element in GF(2)
    pub const ZERO: Self = Self(false);

    /// The one element in GF(2)
    pub const ONE: Self = Self(true);

    /// Create a new field element from a boolean
    pub const fn new(value: bool) -> Self {
        Self(value)
    }

    /// Create a field element from a u8 (0 maps to false, anything else to true)
    pub const fn from_u8(value: u8) -> Self {
        Self(value != 0)
    }

    /// Convert to u8 (false maps to 0, true maps to 1)
    pub const fn to_u8(self) -> u8 {
        if self.0 { 1 } else { 0 }
    }

    /// Check if this is the zero element
    pub const fn is_zero(self) -> bool {
        !self.0
    }

    /// Check if this is the one element
    pub const fn is_one(self) -> bool {
        self.0
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = Self;

    /// Addition in GF(2) is XOR
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = Self;

    /// Subtraction in GF(2) is the same as addition (XOR)
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = Self;

    /// Multiplication in GF(2) is AND
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &FieldElement) -> FieldElement {
        *self + *rhs
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &FieldElement) -> FieldElement {
        *self - *rhs
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        *self * *rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_creation() {
        assert_eq!(FieldElement::ZERO, FieldElement::new(false));
        assert_eq!(FieldElement::ONE, FieldElement::new(true));
        assert_eq!(FieldElement::from_u8(0), FieldElement::ZERO);
        assert_eq!(FieldElement::from_u8(1), FieldElement::ONE);
        assert_eq!(FieldElement::from_u8(42), FieldElement::ONE);
    }

    #[test]
    fn test_field_element_conversion() {
        assert_eq!(FieldElement::ZERO.to_u8(), 0);
        assert_eq!(FieldElement::ONE.to_u8(), 1);
    }

    #[test]
    fn test_field_element_checks() {
        assert!(FieldElement::ZERO.is_zero());
        assert!(!FieldElement::ZERO.is_one());
        assert!(!FieldElement::ONE.is_zero());
        assert!(FieldElement::ONE.is_one());
    }

    #[test]
    fn test_field_element_addition() {
        // 0 + 0 = 0
        assert_eq!(FieldElement::ZERO + FieldElement::ZERO, FieldElement::ZERO);
        // 0 + 1 = 1
        assert_eq!(FieldElement::ZERO + FieldElement::ONE, FieldElement::ONE);
        // 1 + 0 = 1
        assert_eq!(FieldElement::ONE + FieldElement::ZERO, FieldElement::ONE);
        // 1 + 1 = 0 (XOR)
        assert_eq!(FieldElement::ONE + FieldElement::ONE, FieldElement::ZERO);
    }

    #[test]
    fn test_field_element_subtraction() {
        // In GF(2), subtraction is the same as addition
        assert_eq!(FieldElement::ZERO - FieldElement::ZERO, FieldElement::ZERO);
        assert_eq!(FieldElement::ZERO - FieldElement::ONE, FieldElement::ONE);
        assert_eq!(FieldElement::ONE - FieldElement::ZERO, FieldElement::ONE);
        assert_eq!(FieldElement::ONE - FieldElement::ONE, FieldElement::ZERO);
    }

    #[test]
    fn test_field_element_multiplication() {
        // 0 * 0 = 0
        assert_eq!(FieldElement::ZERO * FieldElement::ZERO, FieldElement::ZERO);
        // 0 * 1 = 0
        assert_eq!(FieldElement::ZERO * FieldElement::ONE, FieldElement::ZERO);
        // 1 * 0 = 0
        assert_eq!(FieldElement::ONE * FieldElement::ZERO, FieldElement::ZERO);
        // 1 * 1 = 1
        assert_eq!(FieldElement::ONE * FieldElement::ONE, FieldElement::ONE);
    }

    #[test]
    fn test_field_element_references() {
        let a = FieldElement::ONE;
        let b = FieldElement::ZERO;

        assert_eq!(a + b, FieldElement::ONE);
        assert_eq!(a - b, FieldElement::ONE);
        assert_eq!(a * b, FieldElement::ZERO);
    }
}
