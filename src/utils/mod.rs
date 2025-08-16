//! Utility functions for libQ
//!
//! This module provides common utility functions used throughout the library.

use crate::error::{Error, Result};
use getrandom::getrandom;

/// Constant-time comparison of two byte slices
///
/// This function performs a constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Generate cryptographically secure random bytes
///
/// # Arguments
///
/// * `length` - The number of bytes to generate
///
/// # Returns
///
/// A vector of random bytes
///
/// # Errors
///
/// Returns an error if random number generation fails
pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
    // Validate input
    if length == 0 {
        return Err(Error::InvalidMessageSize { max: 0, actual: 0 });
    }

    // Check for reasonable maximum size (1MB to prevent DoS)
    const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB
    if length > MAX_RANDOM_SIZE {
        return Err(Error::InvalidMessageSize {
            max: MAX_RANDOM_SIZE,
            actual: length,
        });
    }

    let mut bytes = vec![0u8; length];
    getrandom(&mut bytes).map_err(|_| Error::RandomGenerationFailed {
        operation: "random_bytes".to_string(),
    })?;

    Ok(bytes)
}

/// Generate a random nonce
///
/// # Arguments
///
/// * `length` - The length of the nonce
///
/// # Returns
///
/// A random nonce of the specified length
pub fn random_nonce(length: usize) -> Result<Vec<u8>> {
    random_bytes(length)
}

/// Convert bytes to hex string
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
///
/// # Returns
///
/// A hex string representation of the bytes
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert hex string to bytes
///
/// # Arguments
///
/// * `hex` - The hex string to convert
///
/// # Returns
///
/// A vector of bytes
///
/// # Errors
///
/// Returns an error if the hex string is invalid
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    // Validate input
    if hex.is_empty() {
        return Err(Error::InvalidMessageSize { max: 0, actual: 0 });
    }

    if hex.len() % 2 != 0 {
        return Err(Error::InternalError {
            operation: "hex_to_bytes".to_string(),
            details: "Hex string length must be even".to_string(),
        });
    }

    // Check for reasonable maximum size (1MB to prevent DoS)
    const MAX_HEX_SIZE: usize = 1024 * 1024; // 1MB
    if hex.len() > MAX_HEX_SIZE {
        return Err(Error::InvalidMessageSize {
            max: MAX_HEX_SIZE,
            actual: hex.len(),
        });
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Error::InternalError {
            operation: "hex_to_bytes".to_string(),
            details: "Invalid hex character".to_string(),
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Secure memory zeroization
///
/// This function securely zeroizes a byte slice to prevent sensitive data
/// from remaining in memory.
///
/// # Arguments
///
/// * `data` - The data to zeroize
pub fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

/// Validate input data size
///
/// # Arguments
///
/// * `data` - The data to validate
/// * `min_size` - Minimum allowed size
/// * `max_size` - Maximum allowed size
///
/// # Returns
///
/// `Ok(())` if the data size is valid, or an error if not
pub fn validate_data_size(data: &[u8], min_size: usize, max_size: usize) -> Result<()> {
    if data.len() < min_size {
        return Err(Error::InvalidMessageSize {
            max: min_size,
            actual: data.len(),
        });
    }

    if data.len() > max_size {
        return Err(Error::InvalidMessageSize {
            max: max_size,
            actual: data.len(),
        });
    }

    Ok(())
}

/// Generate a random key of specified size
///
/// # Arguments
///
/// * `size` - The size of the key in bytes
///
/// # Returns
///
/// A random key of the specified size
pub fn random_key(size: usize) -> Result<Vec<u8>> {
    // Validate key size
    if size == 0 {
        return Err(Error::InvalidKeySize {
            expected: 1,
            actual: 0,
        });
    }

    // Check for reasonable maximum key size (1MB)
    const MAX_KEY_SIZE: usize = 1024 * 1024; // 1MB
    if size > MAX_KEY_SIZE {
        return Err(Error::InvalidKeySize {
            expected: MAX_KEY_SIZE,
            actual: size,
        });
    }

    random_bytes(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];
        let d = vec![1, 2, 3];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &d));
    }

    #[test]
    fn test_random_bytes() {
        // Test valid sizes
        let bytes1 = random_bytes(16).expect("Random bytes generation should succeed");
        let bytes2 = random_bytes(32).expect("Random bytes generation should succeed");

        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 32);

        // Test that they're different (very unlikely to be the same)
        assert_ne!(bytes1, bytes2);

        // Test invalid sizes
        assert!(random_bytes(0).is_err());
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0123456789abcdef");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "0123456789abcdef";
        let bytes = hex_to_bytes(hex).expect("Hex to bytes conversion should succeed");
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        // Test invalid hex
        assert!(hex_to_bytes("123").is_err()); // Odd length
        assert!(hex_to_bytes("").is_err()); // Empty
    }

    #[test]
    fn test_secure_zeroize() {
        let mut data = vec![1, 2, 3, 4, 5];
        secure_zeroize(&mut data);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_validate_data_size() {
        let data = vec![1, 2, 3, 4];

        // Valid sizes
        assert!(validate_data_size(&data, 1, 10).is_ok());
        assert!(validate_data_size(&data, 4, 4).is_ok());

        // Invalid sizes
        assert!(validate_data_size(&data, 5, 10).is_err()); // Too small
        assert!(validate_data_size(&data, 1, 3).is_err()); // Too large
    }

    #[test]
    fn test_random_key() {
        let key = random_key(32).expect("Random key generation should succeed");
        assert_eq!(key.len(), 32);

        // Test invalid sizes
        assert!(random_key(0).is_err());
    }
}
