//! Verification utilities for recursive STARK proofs
//!
//! This module provides shared utilities for recursive STARK verification,
//! including security checks, constant-time operations, and validation helpers.
//!
//! # Security
//!
//! - All operations use constant-time comparisons where secrets are involved
//! - Input validation prevents DoS attacks
//! - Memory bounds checking prevents exhaustion

extern crate alloc;

use alloc::format;
use alloc::string::String;

use lib_q_stark_field::Field;

/// Constant-time comparison of two field elements
///
/// Returns true if `a == b`, false otherwise.
/// This operation is constant-time to prevent timing attacks.
///
/// # Security
///
/// Uses field subtraction and zero check, which are constant-time operations
/// in most field implementations.
pub fn constant_time_eq<F: Field>(a: &F, b: &F) -> bool {
    // Field subtraction and zero check are typically constant-time
    (*a - *b).is_zero()
}

/// Constant-time comparison of two byte arrays
///
/// Returns true if arrays are equal, false otherwise.
/// This operation is constant-time to prevent timing attacks.
///
/// # Security
///
/// Uses byte-by-byte XOR and OR operations, which are constant-time.
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Constant-time comparison using XOR
    let mut result = 0u8;
    for (ai, bi) in a.iter().zip(b.iter()) {
        result |= ai ^ bi;
    }
    result == 0
}

/// Validate proof size to prevent DoS attacks
///
/// # Arguments
///
/// * `size` - Size in bytes
/// * `max_size` - Maximum allowed size
///
/// # Returns
///
/// `Ok(())` if size is valid, `Err` with reason if invalid
pub fn validate_proof_size(size: usize, max_size: usize) -> Result<(), String> {
    if size > max_size {
        return Err(format!("Proof size {} exceeds maximum {}", size, max_size));
    }
    Ok(())
}

/// Validate array length to prevent DoS attacks
///
/// # Arguments
///
/// * `length` - Array length
/// * `max_length` - Maximum allowed length
/// * `parameter_name` - Name of the parameter for error messages
///
/// # Returns
///
/// `Ok(())` if length is valid, `Err` with reason if invalid
pub fn validate_array_length(
    length: usize,
    max_length: usize,
    parameter_name: &str,
) -> Result<(), String> {
    if length > max_length {
        return Err(format!(
            "{} length {} exceeds maximum {}",
            parameter_name, length, max_length
        ));
    }
    Ok(())
}

/// Validate that a value is within a range
///
/// # Arguments
///
/// * `value` - Value to validate
/// * `min` - Minimum allowed value (inclusive)
/// * `max` - Maximum allowed value (inclusive)
/// * `parameter_name` - Name of the parameter for error messages
///
/// # Returns
///
/// `Ok(())` if value is in range, `Err` with reason if invalid
pub fn validate_range(
    value: usize,
    min: usize,
    max: usize,
    parameter_name: &str,
) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{} value {} is outside valid range [{}, {}]",
            parameter_name, value, min, max
        ));
    }
    Ok(())
}

/// Check if a number is a power of two
///
/// Used for validating domain sizes and other power-of-two requirements.
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

/// Compute the next power of two greater than or equal to n
///
/// Used for padding trace dimensions.
pub fn next_power_of_two_ceil(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    if is_power_of_two(n) {
        return n;
    }
    let mut power = 1;
    while power < n {
        power <<= 1;
    }
    power
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_constant_time_eq() {
        let a = TestField::from_u8(5);
        let b = TestField::from_u8(5);
        let c = TestField::from_u8(6);

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_constant_time_eq_bytes() {
        let a = b"test";
        let b = b"test";
        let c = b"fail";

        assert!(constant_time_eq_bytes(a, b));
        assert!(!constant_time_eq_bytes(a, c));
        assert!(!constant_time_eq_bytes(a, b"test1"));
    }

    #[test]
    fn test_validate_proof_size() {
        assert!(validate_proof_size(100, 1000).is_ok());
        assert!(validate_proof_size(1000, 1000).is_ok());
        assert!(validate_proof_size(1001, 1000).is_err());
    }

    #[test]
    fn test_validate_array_length() {
        assert!(validate_array_length(10, 100, "test").is_ok());
        assert!(validate_array_length(100, 100, "test").is_ok());
        assert!(validate_array_length(101, 100, "test").is_err());
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range(5, 1, 10, "test").is_ok());
        assert!(validate_range(1, 1, 10, "test").is_ok());
        assert!(validate_range(10, 1, 10, "test").is_ok());
        assert!(validate_range(0, 1, 10, "test").is_err());
        assert!(validate_range(11, 1, 10, "test").is_err());
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(8));
        assert!(is_power_of_two(16));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(0));
    }

    #[test]
    fn test_next_power_of_two_ceil() {
        assert_eq!(next_power_of_two_ceil(0), 1);
        assert_eq!(next_power_of_two_ceil(1), 1);
        assert_eq!(next_power_of_two_ceil(2), 2);
        assert_eq!(next_power_of_two_ceil(3), 4);
        assert_eq!(next_power_of_two_ceil(5), 8);
        assert_eq!(next_power_of_two_ceil(8), 8);
    }
}
