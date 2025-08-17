//! lib-Q UTILS - Utility functions for post-quantum cryptography
//!
//! This crate provides utility functions used across lib-Q.

// Re-export core types for public use
pub use lib_q_core::Result;

// TODO: Add submodules when needed

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
        return Err(lib_q_core::Error::InvalidMessageSize { max: 0, actual: 0 });
    }

    // Check for reasonable maximum size (1MB to prevent DoS)
    const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB
    if length > MAX_RANDOM_SIZE {
        return Err(lib_q_core::Error::InvalidMessageSize {
            max: MAX_RANDOM_SIZE,
            actual: length,
        });
    }

    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes).map_err(|_| lib_q_core::Error::RandomGenerationFailed {
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
    // Remove any whitespace
    let hex = hex.trim();

    // Check if the string has an even number of characters
    if hex.len() % 2 != 0 {
        return Err(lib_q_core::Error::InvalidMessageSize { 
            max: 0, actual: hex.len() 
        });
    }

    // Convert hex string to bytes
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| {
            lib_q_core::Error::InvalidMessageSize {
                max: 0, actual: i,
            }
        })?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// Generate a random key
///
/// # Arguments
///
/// * `size` - The size of the key in bytes
///
/// # Returns
///
/// A random key of the specified size
pub fn random_key(size: usize) -> Result<Vec<u8>> {
    random_bytes(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hell"));
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32).expect("Should generate random bytes");
        assert_eq!(bytes.len(), 32);

        // Test that we get different bytes on subsequent calls
        let bytes2 = random_bytes(32).expect("Should generate random bytes");
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_random_bytes_invalid_size() {
        assert!(random_bytes(0).is_err());
        assert!(random_bytes(1024 * 1024 + 1).is_err());
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
        let bytes = hex_to_bytes(hex).expect("Should convert hex to bytes");
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        assert!(hex_to_bytes("123").is_err()); // Odd length
        assert!(hex_to_bytes("12g3").is_err()); // Invalid character
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = bytes_to_hex(&original);
        let converted = hex_to_bytes(&hex).expect("Should convert back to bytes");
        assert_eq!(original, converted);
    }

    #[test]
    fn test_random_nonce() {
        let nonce = random_nonce(16).expect("Should generate random nonce");
        assert_eq!(nonce.len(), 16);
    }

    #[test]
    fn test_random_key() {
        let key = random_key(32).expect("Should generate random key");
        assert_eq!(key.len(), 32);
    }
}
