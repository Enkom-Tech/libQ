//! Utility functions for libQ
//!
//! This module provides common utility functions used throughout the library.

use crate::error::{Error, Result};

/// Constant-time comparison of two byte slices
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

/// Generate random bytes
pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
    Ok(bytes)
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(Error::InternalError {
            operation: "hex_to_bytes".to_string(),
            details: "Hex string length must be even".to_string(),
        });
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| Error::InternalError {
                operation: "hex_to_bytes".to_string(),
                details: "Invalid hex character".to_string(),
            })?;
        bytes.push(byte);
    }
    Ok(bytes)
}
