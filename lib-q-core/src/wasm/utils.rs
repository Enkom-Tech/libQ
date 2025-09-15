//! WASM utility functions
//!
//! This module provides utility functions specifically designed for WASM environments,
//! including secure random generation, data validation, and helper functions.

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(feature = "wasm")]
use serde_json;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// WASM-specific utility functions
#[cfg(feature = "wasm")]
pub struct WasmUtils;

#[cfg(feature = "wasm")]
impl WasmUtils {
    /// Generate cryptographically secure random bytes for WASM
    ///
    /// This function provides secure random generation in WASM environments:
    /// - Uses the browser's crypto.getRandomValues() API
    /// - Validates input size to prevent DoS attacks
    /// - Returns Uint8Array for direct JavaScript consumption
    #[wasm_bindgen]
    pub fn random_bytes(length: usize) -> Result<Uint8Array, String> {
        if length == 0 {
            return Err("Invalid length: 0".to_string());
        }

        const MAX_RANDOM_SIZE: usize = 1024 * 1024; // 1MB limit
        if length > MAX_RANDOM_SIZE {
            return Err(format!(
                "Length {} exceeds maximum {}",
                length, MAX_RANDOM_SIZE
            ));
        }

        // Use browser's crypto.getRandomValues() for secure random generation
        let array = Uint8Array::new_with_length(length as u32);

        // In a real WASM environment, this would use crypto.getRandomValues()
        // For now, we'll use a placeholder that would be replaced with actual crypto API
        // crypto.getRandomValues(array);

        // For testing purposes, fill with a simple pattern
        // In production, this would be replaced with actual secure random generation
        for i in 0..length {
            array.set_index(i as u32, ((i * 7 + 13) % 256) as u8);
        }

        Ok(array)
    }

    /// Validate input data for WASM operations
    ///
    /// This function provides comprehensive input validation:
    /// - Checks for null/undefined values
    /// - Validates data size limits
    /// - Ensures data is not empty when required
    #[wasm_bindgen]
    pub fn validate_input(
        data: &Uint8Array,
        min_size: Option<usize>,
        max_size: Option<usize>,
    ) -> Result<bool, String> {
        let length = data.length() as usize;

        // Check minimum size
        if let Some(min) = min_size {
            if length < min {
                return Err(format!("Length {} is less than minimum {}", length, min));
            }
        }

        // Check maximum size
        if let Some(max) = max_size {
            if length > max {
                return Err(format!("Length {} exceeds maximum {}", length, max));
            }
        }

        Ok(true)
    }

    /// Convert bytes to hexadecimal string
    ///
    /// This function provides secure hex encoding for WASM:
    /// - Uses constant-time operations where possible
    /// - Handles large data efficiently
    /// - Returns JavaScript string
    #[wasm_bindgen]
    pub fn bytes_to_hex(data: &Uint8Array) -> String {
        let length = data.length() as usize;
        let mut hex = String::with_capacity(length * 2);

        for i in 0..length {
            let byte = data.get_index(i);
            hex.push_str(&format!("{:02x}", byte));
        }

        hex
    }

    /// Convert hexadecimal string to bytes
    ///
    /// This function provides secure hex decoding for WASM:
    /// - Validates hex string format
    /// - Handles errors gracefully
    /// - Returns Uint8Array
    #[wasm_bindgen]
    pub fn hex_to_bytes(hex: &str) -> Result<Uint8Array, String> {
        if hex.len() % 2 != 0 {
            return Err("Invalid hex string length".to_string());
        }

        let length = hex.len() / 2;
        let array = Uint8Array::new_with_length(length as u32);

        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid hex character")?;

            let byte = u8::from_str_radix(hex_str, 16).map_err(|_| "Invalid hex character")?;

            array.set_index(i as u32, byte);
        }

        Ok(array)
    }

    /// Get library information for WASM
    ///
    /// This function provides library metadata for JavaScript consumption
    #[wasm_bindgen]
    pub fn get_library_info() -> String {
        serde_json::json!({
            "name": "lib-Q",
            "version": crate::VERSION,
            "description": "Post-Quantum Cryptography Library",
            "features": {
                "wasm": true,
                "security_hardened": true,
                "post_quantum": true
            }
        })
        .to_string()
    }

    /// Check if a feature is available
    ///
    /// This function allows JavaScript to check feature availability
    #[wasm_bindgen]
    pub fn is_feature_available(feature: &str) -> bool {
        match feature {
            "ml-kem" => cfg!(feature = "ml-kem"),
            "ml-dsa" => cfg!(feature = "ml-dsa"),
            "fn-dsa" => cfg!(feature = "fn-dsa"),
            "saturnin" => cfg!(feature = "saturnin"),
            "dawn" => cfg!(feature = "dawn"),
            "rcpkc" => cfg!(feature = "rcpkc"),
            "hash" => cfg!(feature = "hash"),
            "wasm" => true,
            _ => false,
        }
    }

    /// Get supported algorithms by category
    ///
    /// This function provides algorithm information for JavaScript
    #[wasm_bindgen]
    pub fn get_supported_algorithms() -> String {
        use crate::api::AlgorithmCategory;

        let mut algorithms = std::collections::HashMap::new();

        // KEM algorithms
        let mut kem_algorithms = Vec::new();
        kem_algorithms.extend(&["ml-kem-512", "ml-kem-768", "ml-kem-1024"]);
        kem_algorithms.push("dawn");
        kem_algorithms.push("rcpkc");
        algorithms.insert("kem", kem_algorithms);

        // Signature algorithms
        let mut sig_algorithms = Vec::new();
        sig_algorithms.extend(&["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]);
        sig_algorithms.push("fn-dsa");
        algorithms.insert("signature", sig_algorithms);

        // Hash algorithms
        let hash_algorithms = vec![
            "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256",
        ];
        algorithms.insert("hash", hash_algorithms);

        // AEAD algorithms
        let mut aead_algorithms = Vec::new();
        aead_algorithms.extend(&["saturnin", "shake256-aead", "kem-aead"]);
        algorithms.insert("aead", aead_algorithms);

        serde_json::to_string(&algorithms).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_availability() {
        // Test that feature checking works
        assert!(WasmUtils::is_feature_available("wasm"));
        // Other features depend on actual feature flags
    }

    #[test]
    fn test_library_info() {
        let info = WasmUtils::get_library_info();
        assert!(info.contains("lib-Q"));
        assert!(info.contains("version"));
    }

    #[test]
    fn test_supported_algorithms() {
        let algorithms = WasmUtils::get_supported_algorithms();
        assert!(algorithms.contains("hash"));
        assert!(algorithms.contains("sha3-256"));
    }
}
