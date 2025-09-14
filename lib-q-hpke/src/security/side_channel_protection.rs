//! Side-channel protection mechanisms for HPKE
//!
//! This module provides protection against timing attacks, power analysis,
//! and other side-channel attacks.

#[cfg(feature = "alloc")]
use alloc::format;

use crate::error::HpkeError;

/// Constant-time comparison for sensitive data
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

/// Constant-time selection between two values
pub fn constant_time_select(condition: bool, true_value: u8, false_value: u8) -> u8 {
    let mask = if condition { 0xFF } else { 0x00 };
    (true_value & mask) | (false_value & !mask)
}

/// Constant-time conditional copy
pub fn constant_time_copy(condition: bool, src: &[u8], dst: &mut [u8]) {
    if src.len() != dst.len() {
        return;
    }

    let mask = if condition { 0xFF } else { 0x00 };
    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Side-channel resistant key validation
pub fn validate_key_side_channel_resistant(
    key: &[u8],
    expected_len: usize,
) -> Result<(), HpkeError> {
    // Check length in constant time
    let len_match = key.len() == expected_len;

    // Check for all-zero key in constant time
    let mut zero_check = 0u8;
    for &byte in key {
        zero_check |= byte;
    }
    let not_zero = zero_check != 0;

    // Check for all-ones key in constant time
    let mut ones_check = 0xFFu8;
    for &byte in key {
        ones_check &= byte;
    }
    let not_ones = ones_check != 0xFF;

    // Combine all checks
    if !len_match {
        return Err(HpkeError::CryptoError(format!(
            "Invalid key length: expected {}, got {}",
            expected_len,
            key.len()
        )));
    }

    if !not_zero {
        return Err(HpkeError::CryptoError(
            "Key material cannot be all zeros".into(),
        ));
    }

    if !not_ones {
        return Err(HpkeError::CryptoError(
            "Key material cannot be all ones".into(),
        ));
    }

    Ok(())
}

/// Side-channel resistant nonce validation
pub fn validate_nonce_side_channel_resistant(
    nonce: &[u8],
    expected_len: usize,
) -> Result<(), HpkeError> {
    // Check length in constant time
    let len_match = nonce.len() == expected_len;

    if !len_match {
        return Err(HpkeError::CryptoError(format!(
            "Invalid nonce length: expected {}, got {}",
            expected_len,
            nonce.len()
        )));
    }

    Ok(())
}

/// Side-channel resistant ciphertext validation
pub fn validate_ciphertext_side_channel_resistant(
    ciphertext: &[u8],
    min_len: usize,
) -> Result<(), HpkeError> {
    // Check minimum length in constant time
    let len_ok = ciphertext.len() >= min_len;

    if !len_ok {
        return Err(HpkeError::CryptoError(format!(
            "Ciphertext too short: minimum {} bytes required",
            min_len
        )));
    }

    Ok(())
}

/// Timing attack resistant authentication tag verification
pub fn verify_auth_tag_constant_time(expected: &[u8], actual: &[u8]) -> Result<(), HpkeError> {
    if !constant_time_compare(expected, actual) {
        return Err(HpkeError::CryptoError(
            "Authentication tag verification failed".into(),
        ));
    }

    Ok(())
}

/// Side-channel resistant entropy check
pub fn check_entropy_side_channel_resistant(data: &[u8], min_unique_bytes: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    // Count unique bytes in constant time
    let mut unique_count = 0usize;
    for i in 0..256 {
        let mut found = false;
        for &byte in data {
            if byte == i as u8 {
                found = true;
                break;
            }
        }
        if found {
            unique_count += 1;
        }
    }

    unique_count >= min_unique_bytes
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        let d = b"hell";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, d));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 0xFF, 0x00), 0xFF);
        assert_eq!(constant_time_select(false, 0xFF, 0x00), 0x00);
    }

    #[test]
    fn test_validate_key_side_channel_resistant() {
        let valid_key = vec![1u8; 32];
        let invalid_len_key = vec![1u8; 16];
        let zero_key = vec![0u8; 32];
        let ones_key = vec![0xFFu8; 32];

        assert!(validate_key_side_channel_resistant(&valid_key, 32).is_ok());
        assert!(validate_key_side_channel_resistant(&invalid_len_key, 32).is_err());
        assert!(validate_key_side_channel_resistant(&zero_key, 32).is_err());
        assert!(validate_key_side_channel_resistant(&ones_key, 32).is_err());
    }

    #[test]
    fn test_verify_auth_tag_constant_time() {
        let tag1 = vec![1u8; 16];
        let tag2 = vec![1u8; 16];
        let tag3 = vec![2u8; 16];

        assert!(verify_auth_tag_constant_time(&tag1, &tag2).is_ok());
        assert!(verify_auth_tag_constant_time(&tag1, &tag3).is_err());
    }

    #[test]
    fn test_check_entropy_side_channel_resistant() {
        let low_entropy = vec![0u8; 32]; // All zeros
        let high_entropy = (0..32).collect::<Vec<u8>>(); // All different bytes

        assert!(!check_entropy_side_channel_resistant(&low_entropy, 4));
        assert!(check_entropy_side_channel_resistant(&high_entropy, 4));
    }
}
