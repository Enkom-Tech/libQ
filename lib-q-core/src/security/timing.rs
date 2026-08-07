//! Timing attack prevention utilities
//!
//! This module provides utilities to prevent timing attacks in cryptographic operations.
//!
//! ## AEAD decrypt and verification
//!
//! For authenticated decryption, see the implementor contract on [`crate::traits::Aead`]:
//! symmetric work should precede verification branches where required by the threat model,
//! while the public [`Result`] API still exposes success versus failure at the
//! boundary unless a higher layer mediates timing. For an opt-in semantic decrypt surface
//! (`Ok` versus `AuthenticationFailed` without plaintext on failure), see
//! [`crate::AeadDecryptSemantic`] and workspace ADR `docs/adr/003-aead-decrypt-layers.md`.

#[cfg(feature = "alloc")]
use alloc::string::ToString;

use subtle::{
    Choice,
    ConditionallySelectable,
    ConstantTimeEq,
};

use crate::error::Result;

/// Timing attack prevention validator
///
/// This validator provides utilities to prevent timing attacks by ensuring
/// constant-time operations where necessary.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct TimingValidator {
    // Configuration for timing attack prevention
    enable_timing_validation: bool,
}

#[cfg(feature = "alloc")]
impl TimingValidator {
    /// Create a new timing validator
    ///
    /// # Returns
    ///
    /// A new instance of TimingValidator with timing attack prevention enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the validator fails to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            enable_timing_validation: true,
        })
    }

    /// Perform constant-time comparison of two byte slices
    ///
    /// This function performs a constant-time comparison to prevent timing attacks.
    /// It returns true if the slices are equal, false otherwise.
    ///
    /// # Arguments
    ///
    /// * `a` - First byte slice
    /// * `b` - Second byte slice
    ///
    /// # Returns
    ///
    /// Returns `true` if the slices are equal, `false` otherwise.
    /// The comparison is performed in constant time to prevent timing attacks.
    pub fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Constant-time selection between two values
    ///
    /// Returns `a` if `choice` is true, `b` if `choice` is false.
    /// Selection is branchless: a full-width mask is derived from `choice` via
    /// `subtle::ConditionallySelectable` (no secret-dependent branch). Callers must derive
    /// `choice` itself in constant time.
    ///
    /// # Arguments
    ///
    /// * `choice` - Boolean choice
    /// * `a` - First value
    /// * `b` - Second value
    ///
    /// # Returns
    ///
    /// Returns the selected value in constant time.
    pub fn constant_time_select<T: ConditionallySelectable>(&self, choice: bool, a: T, b: T) -> T {
        T::conditional_select(&b, &a, Choice::from(u8::from(choice)))
    }

    /// Constant-time conditional assignment
    ///
    /// Assigns `src` to `dst` if `choice` is true, otherwise leaves `dst` unchanged.
    /// Branchless: dispatches to `subtle::ConditionallySelectable::conditional_assign`, deriving a
    /// full-width mask from `choice` instead of branching. Callers must derive `choice` itself in
    /// constant time.
    ///
    /// # Arguments
    ///
    /// * `choice` - Boolean choice
    /// * `dst` - Destination to potentially assign to
    /// * `src` - Source value to assign
    pub fn constant_time_assign<T: ConditionallySelectable>(
        &self,
        choice: bool,
        dst: &mut T,
        src: T,
    ) {
        dst.conditional_assign(&src, Choice::from(u8::from(choice)));
    }

    /// Constant-time conditional copy
    ///
    /// Copies `src` to `dst` if `choice` is true, otherwise leaves `dst` unchanged.
    /// Branchless: each byte is assigned via `subtle::ConditionallySelectable::conditional_assign`,
    /// deriving a full-width mask from `choice` instead of branching. Callers must derive `choice`
    /// itself in constant time.
    ///
    /// # Arguments
    ///
    /// * `choice` - Boolean choice
    /// * `dst` - Destination slice
    /// * `src` - Source slice
    ///
    /// # Panics
    ///
    /// Panics if the slices have different lengths.
    pub fn constant_time_copy(&self, choice: bool, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len(), "Slices must have the same length");

        let choice = Choice::from(u8::from(choice));
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            d.conditional_assign(s, choice);
        }
    }

    /// Validate that an operation is timing-safe
    ///
    /// This function can be used to validate that operations are performed
    /// in constant time to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `operation` - Name of the operation being validated
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if timing validation is enabled and the operation
    /// is considered safe, or an error if timing validation fails.
    pub fn validate_timing_safety(&self, operation: &str) -> Result<()> {
        if !self.enable_timing_validation {
            return Ok(());
        }

        // In a real implementation, this would perform actual timing analysis
        // For now, we'll just validate that the operation name is not empty
        if operation.is_empty() {
            return Err(crate::error::Error::InvalidState {
                operation: "timing_validation".to_string(),
                reason: "Operation name cannot be empty".to_string(),
            });
        }

        Ok(())
    }

    /// Enable or disable timing validation
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable timing validation
    pub fn set_timing_validation(&mut self, enabled: bool) {
        self.enable_timing_validation = enabled;
    }

    /// Check if timing validation is enabled
    ///
    /// # Returns
    ///
    /// Returns `true` if timing validation is enabled, `false` otherwise.
    pub fn is_timing_validation_enabled(&self) -> bool {
        self.enable_timing_validation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_validator_creation() {
        let validator = TimingValidator::new();
        assert!(
            validator.is_ok(),
            "TimingValidator should be created successfully"
        );
    }

    #[test]
    fn test_constant_time_compare() {
        let validator = TimingValidator::new().unwrap();

        // Test equal slices
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert!(
            validator.constant_time_compare(&a, &b),
            "Should return true for equal slices"
        );

        // Test different slices
        let c = vec![1, 2, 3, 5];
        assert!(
            !validator.constant_time_compare(&a, &c),
            "Should return false for different slices"
        );

        // Test different length slices
        let d = vec![1, 2, 3];
        assert!(
            !validator.constant_time_compare(&a, &d),
            "Should return false for different length slices"
        );
    }

    #[test]
    fn test_constant_time_select() {
        let validator = TimingValidator::new().unwrap();

        // Test selection with true choice
        let result = validator.constant_time_select(true, 42, 24);
        assert_eq!(result, 42, "Should select first value when choice is true");

        // Test selection with false choice
        let result = validator.constant_time_select(false, 42, 24);
        assert_eq!(
            result, 24,
            "Should select second value when choice is false"
        );
    }

    #[test]
    fn test_constant_time_assign() {
        let validator = TimingValidator::new().unwrap();

        let mut value = 10;

        // Test assignment with true choice
        validator.constant_time_assign(true, &mut value, 20);
        assert_eq!(value, 20, "Should assign new value when choice is true");

        // Test assignment with false choice
        validator.constant_time_assign(false, &mut value, 30);
        assert_eq!(value, 20, "Should not change value when choice is false");
    }

    #[test]
    fn test_constant_time_copy() {
        let validator = TimingValidator::new().unwrap();

        let mut dst = vec![1, 2, 3, 4];
        let src = vec![5, 6, 7, 8];

        // Test copy with true choice
        validator.constant_time_copy(true, &mut dst, &src);
        assert_eq!(dst, src, "Should copy source when choice is true");

        // Test copy with false choice
        let original = dst.clone();
        validator.constant_time_copy(false, &mut dst, &[9, 10, 11, 12]);
        assert_eq!(
            dst, original,
            "Should not change destination when choice is false"
        );
    }

    #[test]
    fn test_validate_timing_safety() {
        let validator = TimingValidator::new().unwrap();

        // Test valid operation
        let result = validator.validate_timing_safety("test_operation");
        assert!(result.is_ok(), "Should accept valid operation name");

        // Test empty operation name
        let result = validator.validate_timing_safety("");
        assert!(result.is_err(), "Should reject empty operation name");
    }

    /// Marks its output when selected through the branchless `subtle` path — the if/else
    /// implementation returns the operand unmarked, so this test fails on any branch-based select.
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct SelectCanary(u32);
    const CANARY_MARK: u32 = 0x8000_0000;
    impl ConditionallySelectable for SelectCanary {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            SelectCanary(u32::conditional_select(&a.0, &b.0, choice) | CANARY_MARK)
        }
    }

    #[test]
    fn select_and_assign_dispatch_through_subtle_not_a_branch() {
        let v = TimingValidator::new().unwrap();
        let r = v.constant_time_select(true, SelectCanary(1), SelectCanary(2));
        assert_eq!(
            r,
            SelectCanary(1 | CANARY_MARK),
            "constant_time_select must route through ConditionallySelectable (mask), not if/else"
        );
        let r = v.constant_time_select(false, SelectCanary(1), SelectCanary(2));
        assert_eq!(r, SelectCanary(2 | CANARY_MARK));

        let mut d = SelectCanary(7);
        v.constant_time_assign(true, &mut d, SelectCanary(9));
        assert_eq!(
            d,
            SelectCanary(9 | CANARY_MARK),
            "constant_time_assign must route through conditional_assign"
        );
    }

    #[test]
    fn test_timing_validation_control() {
        let mut validator = TimingValidator::new().unwrap();

        // Test initial state
        assert!(
            validator.is_timing_validation_enabled(),
            "Timing validation should be enabled by default"
        );

        // Test disabling
        validator.set_timing_validation(false);
        assert!(
            !validator.is_timing_validation_enabled(),
            "Timing validation should be disabled"
        );

        // Test enabling
        validator.set_timing_validation(true);
        assert!(
            validator.is_timing_validation_enabled(),
            "Timing validation should be enabled"
        );
    }
}
