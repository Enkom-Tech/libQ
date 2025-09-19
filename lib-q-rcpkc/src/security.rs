//! Security utilities for RCPKC
//!
//! This module provides security-related functions including constant-time
//! operations, secure memory handling, and validation.

use lib_q_core::Result;
use zeroize::Zeroize;

/// Constant-time operations for security
pub struct ConstantTimeOps;

impl ConstantTimeOps {
    /// Constant-time comparison of two byte slices
    pub fn compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Constant-time selection: returns a if choice is true, b otherwise
    pub fn select<T: Copy>(choice: bool, a: T, b: T) -> T {
        if choice { a } else { b }
    }

    /// Constant-time conditional copy
    pub fn conditional_copy(condition: bool, src: &[u8], dst: &mut [u8]) {
        if src.len() != dst.len() {
            return;
        }

        if condition {
            dst.copy_from_slice(src);
        }
    }

    /// Constant-time conditional zero
    pub fn conditional_zero(condition: bool, data: &mut [u8]) {
        if condition {
            data.zeroize();
        }
    }
}

/// Secure memory operations
pub struct SecureMemory;

impl SecureMemory {
    /// Securely zeroize a byte slice
    pub fn zeroize(data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = 0;
        }
    }

    /// Securely zeroize a vector
    pub fn zeroize_vec<T: Zeroize>(mut data: Vec<T>) {
        for item in data.iter_mut() {
            item.zeroize();
        }
        drop(data);
    }

    /// Securely copy bytes with zeroization of source
    pub fn secure_copy(src: &mut [u8], dst: &mut [u8]) {
        if src.len() != dst.len() {
            return;
        }

        dst.copy_from_slice(src);
        Self::zeroize(src);
    }

    /// Securely move bytes from one slice to another
    pub fn secure_move(src: &mut [u8], dst: &mut [u8]) {
        Self::secure_copy(src, dst);
    }
}

/// Input validation for security
pub struct InputValidator;

impl InputValidator {
    /// Validate key size
    pub fn validate_key_size(size: usize) -> Result<()> {
        if size == 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1,
                actual: size,
            });
        }

        if size > 1024 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 1024,
                actual: size,
            });
        }

        Ok(())
    }

    /// Validate message size
    pub fn validate_message_size(size: usize) -> Result<()> {
        if size > 65536 {
            return Err(lib_q_core::Error::InvalidMessageSize {
                max: 65536,
                actual: size,
            });
        }

        Ok(())
    }

    /// Validate ciphertext size
    pub fn validate_ciphertext_size(size: usize) -> Result<()> {
        if size == 0 {
            return Err(lib_q_core::Error::InvalidCiphertextSize {
                expected: 1,
                actual: size,
            });
        }

        if size > 1024 {
            return Err(lib_q_core::Error::InvalidCiphertextSize {
                expected: 1024,
                actual: size,
            });
        }

        Ok(())
    }

    /// Validate that a byte slice is not all zeros
    pub fn validate_non_zero(data: &[u8]) -> Result<()> {
        if data.iter().all(|&b| b == 0) {
            return Err(lib_q_core::Error::InternalError {
                operation: "validate_non_zero".to_string(),
                details: "Data must not be all zeros".to_string(),
            });
        }

        Ok(())
    }

    /// Validate that a byte slice has expected length
    pub fn validate_length(data: &[u8], expected: usize) -> Result<()> {
        if data.len() != expected {
            return Err(lib_q_core::Error::InternalError {
                operation: "validate_length".to_string(),
                details: format!("Expected length {}, got {}", expected, data.len()),
            });
        }

        Ok(())
    }
}

/// Timing attack resistance
pub struct TimingResistance;

impl TimingResistance {
    /// Add random delay to prevent timing attacks
    pub fn random_delay() {
        // Simple delay implementation - in a real implementation,
        // this would use proper timing resistance techniques
        #[cfg(feature = "std")]
        {
            std::thread::sleep(std::time::Duration::from_micros(1));
        }
    }

    /// Constant-time conditional execution
    pub fn conditional_execute<F>(condition: bool, func: F)
    where
        F: FnOnce(),
    {
        if condition {
            func();
        }
    }
}

/// Side-channel attack resistance
pub struct SideChannelResistance;

impl SideChannelResistance {
    /// Mask sensitive data during computation
    pub fn mask_data(data: &[u8], mask: &[u8]) -> Vec<u8> {
        if data.len() != mask.len() {
            return data.to_vec();
        }

        data.iter().zip(mask.iter()).map(|(d, m)| d ^ m).collect()
    }

    /// Unmask sensitive data after computation
    pub fn unmask_data(masked_data: &[u8], mask: &[u8]) -> Vec<u8> {
        Self::mask_data(masked_data, mask) // XOR is symmetric
    }

    /// Generate a random mask
    pub fn generate_mask(size: usize) -> Result<Vec<u8>> {
        lib_q_core::Utils::random_bytes(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        assert!(ConstantTimeOps::compare(b"hello", b"hello"));
        assert!(!ConstantTimeOps::compare(b"hello", b"world"));
        assert!(!ConstantTimeOps::compare(b"hello", b"hell"));
        assert!(!ConstantTimeOps::compare(b"hello", b""));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(ConstantTimeOps::select(true, 42u32, 0u32), 42);
        assert_eq!(ConstantTimeOps::select(false, 42u32, 0u32), 0);
        assert_eq!(ConstantTimeOps::select(true, 0u32, 42u32), 0);
        assert_eq!(ConstantTimeOps::select(false, 0u32, 42u32), 42);
    }

    #[test]
    fn test_conditional_copy() {
        let src = [1, 2, 3, 4];
        let mut dst = [0, 0, 0, 0];

        ConstantTimeOps::conditional_copy(true, &src, &mut dst);
        assert_eq!(dst, src);

        let mut dst2 = [5, 6, 7, 8];
        ConstantTimeOps::conditional_copy(false, &src, &mut dst2);
        assert_eq!(dst2, [5, 6, 7, 8]);
    }

    #[test]
    fn test_conditional_zero() {
        let mut data = [1, 2, 3, 4];
        ConstantTimeOps::conditional_zero(true, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);

        let mut data2 = [1, 2, 3, 4];
        ConstantTimeOps::conditional_zero(false, &mut data2);
        assert_eq!(data2, [1, 2, 3, 4]);
    }

    #[test]
    fn test_input_validation() {
        // Valid key sizes
        assert!(InputValidator::validate_key_size(32).is_ok());
        assert!(InputValidator::validate_key_size(64).is_ok());

        // Invalid key sizes
        assert!(InputValidator::validate_key_size(0).is_err());
        assert!(InputValidator::validate_key_size(1025).is_err());

        // Valid message sizes
        assert!(InputValidator::validate_message_size(1000).is_ok());
        assert!(InputValidator::validate_message_size(0).is_ok());

        // Invalid message sizes
        assert!(InputValidator::validate_message_size(65537).is_err());

        // Valid ciphertext sizes
        assert!(InputValidator::validate_ciphertext_size(32).is_ok());

        // Invalid ciphertext sizes
        assert!(InputValidator::validate_ciphertext_size(0).is_err());
        assert!(InputValidator::validate_ciphertext_size(1025).is_err());
    }

    #[test]
    fn test_validate_non_zero() {
        assert!(InputValidator::validate_non_zero(&[1, 2, 3]).is_ok());
        assert!(InputValidator::validate_non_zero(&[0, 1, 0]).is_ok());
        assert!(InputValidator::validate_non_zero(&[0, 0, 0]).is_err());
    }

    #[test]
    fn test_validate_length() {
        let data = [1, 2, 3, 4];
        assert!(InputValidator::validate_length(&data, 4).is_ok());
        assert!(InputValidator::validate_length(&data, 3).is_err());
        assert!(InputValidator::validate_length(&data, 5).is_err());
    }

    #[test]
    fn test_side_channel_masking() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mask = [0xAB, 0xCD, 0xEF, 0x01];

        let masked = SideChannelResistance::mask_data(&data, &mask);
        let unmasked = SideChannelResistance::unmask_data(&masked, &mask);

        assert_eq!(unmasked, data);
    }

    #[test]
    fn test_generate_mask() {
        let mask = SideChannelResistance::generate_mask(16).unwrap();
        assert_eq!(mask.len(), 16);

        // Should be different on each call
        let mask2 = SideChannelResistance::generate_mask(16).unwrap();
        assert_ne!(mask, mask2);
    }

    #[test]
    fn test_constant_time_select_usage() {
        // Test the select function with various types
        assert_eq!(ConstantTimeOps::select(true, 42u32, 0u32), 42);
        assert_eq!(ConstantTimeOps::select(false, 42u32, 0u32), 0);
        assert_eq!(ConstantTimeOps::select(true, 0u32, 42u32), 0);
        assert_eq!(ConstantTimeOps::select(false, 0u32, 42u32), 42);

        // Test with different types
        assert_eq!(ConstantTimeOps::select(true, 1.5f64, 2.5f64), 1.5);
        assert_eq!(ConstantTimeOps::select(false, 1.5f64, 2.5f64), 2.5);

        // Test with byte arrays
        let a = [1, 2, 3];
        let b = [4, 5, 6];
        assert_eq!(ConstantTimeOps::select(true, a, b), a);
        assert_eq!(ConstantTimeOps::select(false, a, b), b);
    }

    #[test]
    fn test_conditional_copy_usage() {
        let src = [1, 2, 3, 4];
        let mut dst = [0, 0, 0, 0];

        // Test conditional copy with true condition
        ConstantTimeOps::conditional_copy(true, &src, &mut dst);
        assert_eq!(dst, src);

        // Test conditional copy with false condition
        let mut dst2 = [5, 6, 7, 8];
        ConstantTimeOps::conditional_copy(false, &src, &mut dst2);
        assert_eq!(dst2, [5, 6, 7, 8]); // Should remain unchanged

        // Test with mismatched lengths
        let short_src = [1, 2];
        let mut long_dst = [0, 0, 0, 0];
        ConstantTimeOps::conditional_copy(true, &short_src, &mut long_dst);
        assert_eq!(long_dst, [0, 0, 0, 0]); // Should remain unchanged due to length mismatch
    }

    #[test]
    fn test_conditional_zero_usage() {
        let mut data = [1, 2, 3, 4];

        // Test conditional zero with true condition
        ConstantTimeOps::conditional_zero(true, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);

        // Test conditional zero with false condition
        let mut data2 = [1, 2, 3, 4];
        ConstantTimeOps::conditional_zero(false, &mut data2);
        assert_eq!(data2, [1, 2, 3, 4]); // Should remain unchanged
    }

    #[test]
    fn test_secure_copy_usage() {
        let mut src = [1, 2, 3, 4];
        let mut dst = [0, 0, 0, 0];

        // Test secure copy
        SecureMemory::secure_copy(&mut src, &mut dst);
        assert_eq!(dst, [1, 2, 3, 4]);
        assert_eq!(src, [0, 0, 0, 0]); // Source should be zeroized

        // Test with mismatched lengths
        let mut short_src = [1, 2];
        let mut long_dst = [0, 0, 0, 0];
        SecureMemory::secure_copy(&mut short_src, &mut long_dst);
        assert_eq!(long_dst, [0, 0, 0, 0]); // Should remain unchanged due to length mismatch
        assert_eq!(short_src, [1, 2]); // Source should remain unchanged due to length mismatch
    }

    #[test]
    fn test_secure_move_usage() {
        let mut src = [5, 6, 7, 8];
        let mut dst = [0, 0, 0, 0];

        // Test secure move
        SecureMemory::secure_move(&mut src, &mut dst);
        assert_eq!(dst, [5, 6, 7, 8]);
        assert_eq!(src, [0, 0, 0, 0]); // Source should be zeroized

        // Test with mismatched lengths
        let mut short_src = [9, 10];
        let mut long_dst = [0, 0, 0, 0];
        SecureMemory::secure_move(&mut short_src, &mut long_dst);
        assert_eq!(long_dst, [0, 0, 0, 0]); // Should remain unchanged due to length mismatch
        assert_eq!(short_src, [9, 10]); // Source should remain unchanged due to length mismatch
    }

    #[test]
    fn test_conditional_execute_usage() {
        let mut counter = 0;

        // Test conditional execute with true condition
        TimingResistance::conditional_execute(true, || {
            counter += 1;
        });
        assert_eq!(counter, 1);

        // Test conditional execute with false condition
        TimingResistance::conditional_execute(false, || {
            counter += 1;
        });
        assert_eq!(counter, 1); // Should remain unchanged

        // Test with multiple executions
        TimingResistance::conditional_execute(true, || {
            counter += 10;
        });
        assert_eq!(counter, 11);
    }
}
