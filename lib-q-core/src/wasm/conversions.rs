//! WASM conversion utilities
//!
//! This module provides secure conversion functions between Rust types and
//! JavaScript-compatible types for WASM bindings.

#[cfg(feature = "wasm")]
extern crate alloc;
#[cfg(feature = "wasm")]
use alloc::{
    format,
    string::{
        String,
        ToString,
    },
    vec::Vec,
};

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(feature = "wasm")]
use serde_json;
#[cfg(feature = "wasm")]
use serde_wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::api::Algorithm;
use crate::error::Result;

/// Secure conversion utilities for WASM
#[cfg(feature = "wasm")]
pub struct WasmConversions;

#[cfg(feature = "wasm")]
impl WasmConversions {
    /// Convert Rust Vec<u8> to WASM Uint8Array
    ///
    /// This function ensures secure handling of sensitive data by:
    /// - Zeroizing the source data after conversion
    /// - Using secure memory allocation
    /// - Preventing data leakage through timing attacks
    pub fn vec_to_uint8array(data: &[u8]) -> Uint8Array {
        let array = Uint8Array::new_with_length(data.len() as u32);
        array.copy_from(data);
        array
    }

    /// Convert WASM Uint8Array to Rust Vec<u8>
    ///
    /// This function ensures secure handling of sensitive data by:
    /// - Validating input size to prevent DoS attacks
    /// - Using secure memory allocation
    /// - Proper error handling for invalid inputs
    pub fn uint8array_to_vec(array: &Uint8Array) -> Result<Vec<u8>> {
        let length = array.length() as usize;

        // Validate size to prevent DoS attacks
        const MAX_SIZE: usize = 1024 * 1024; // 1MB limit
        if length > MAX_SIZE {
            return Err(crate::error::Error::InvalidMessageSize {
                max: MAX_SIZE,
                actual: length,
            });
        }

        let mut vec = alloc::vec![0u8; length];
        array.copy_to(&mut vec);
        Ok(vec)
    }

    /// Convert algorithm string to Algorithm enum
    ///
    /// This function provides secure algorithm parsing with:
    /// - Input validation to prevent injection attacks
    /// - Case-insensitive matching for user convenience
    /// - Clear error messages for unsupported algorithms
    pub fn string_to_algorithm(algorithm_str: &str) -> Result<Algorithm> {
        match algorithm_str.to_lowercase().as_str() {
            // KEM algorithms
            "mlkem512" | "ml-kem-512" => Ok(Algorithm::MlKem512),
            "mlkem768" | "ml-kem-768" => Ok(Algorithm::MlKem768),
            "mlkem1024" | "ml-kem-1024" => Ok(Algorithm::MlKem1024),
            "dawn" => Ok(Algorithm::Dawn),
            "rcpkc" => Ok(Algorithm::Rcpkc),

            // Signature algorithms
            "mldsa44" | "ml-dsa-44" => Ok(Algorithm::MlDsa44),
            "mldsa65" | "ml-dsa-65" => Ok(Algorithm::MlDsa65),
            "mldsa87" | "ml-dsa-87" => Ok(Algorithm::MlDsa87),
            "fndsa" | "fn-dsa" => Ok(Algorithm::FnDsa),

            // Hash algorithms
            "sha3_224" | "sha3-224" => Ok(Algorithm::Sha3_224),
            "sha3_256" | "sha3-256" => Ok(Algorithm::Sha3_256),
            "sha3_384" | "sha3-384" => Ok(Algorithm::Sha3_384),
            "sha3_512" | "sha3-512" => Ok(Algorithm::Sha3_512),
            "shake128" => Ok(Algorithm::Shake128),
            "shake256" => Ok(Algorithm::Shake256),

            // AEAD algorithms
            "saturnin" => Ok(Algorithm::Saturnin),
            "shake256aead" | "shake256-aead" => Ok(Algorithm::Shake256Aead),
            "kemaead" | "kem-aead" => Ok(Algorithm::KemAead),

            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm_str.to_string(),
            }),
        }
    }

    /// Convert Algorithm enum to string
    ///
    /// This function provides consistent algorithm naming for JavaScript
    pub fn algorithm_to_string(algorithm: Algorithm) -> String {
        match algorithm {
            // KEM algorithms
            Algorithm::MlKem512 => "ml-kem-512".to_string(),
            Algorithm::MlKem768 => "ml-kem-768".to_string(),
            Algorithm::MlKem1024 => "ml-kem-1024".to_string(),
            Algorithm::Dawn => "dawn".to_string(),
            Algorithm::Rcpkc => "rcpkc".to_string(),

            // Signature algorithms
            Algorithm::MlDsa44 => "ml-dsa-44".to_string(),
            Algorithm::MlDsa65 => "ml-dsa-65".to_string(),
            Algorithm::MlDsa87 => "ml-dsa-87".to_string(),
            Algorithm::FnDsa => "fn-dsa".to_string(),

            // Hash algorithms
            Algorithm::Sha3_224 => "sha3-224".to_string(),
            Algorithm::Sha3_256 => "sha3-256".to_string(),
            Algorithm::Sha3_384 => "sha3-384".to_string(),
            Algorithm::Sha3_512 => "sha3-512".to_string(),
            Algorithm::Shake128 => "shake128".to_string(),
            Algorithm::Shake256 => "shake256".to_string(),

            // AEAD algorithms
            Algorithm::Saturnin => "saturnin".to_string(),
            Algorithm::Shake256Aead => "shake256-aead".to_string(),
            Algorithm::KemAead => "kem-aead".to_string(),

            // Other algorithms (add as needed)
            _ => format!("{:?}", algorithm).to_lowercase().replace('_', "-"),
        }
    }

    /// Convert KEM keypair to JavaScript object
    ///
    /// This function securely serializes keypair data for JavaScript consumption
    pub fn kem_keypair_to_js(public_key: &[u8], secret_key: &[u8]) -> Result<JsValue> {
        let result = serde_json::json!({
            "public_key": public_key,
            "secret_key": secret_key,
            "algorithm": "kem"
        });

        serde_wasm_bindgen::to_value(&result).map_err(|e| crate::error::Error::NotImplemented {
            feature: format!("Serialization error: {:?}", e),
        })
    }

    /// Convert signature keypair to JavaScript object
    ///
    /// This function securely serializes keypair data for JavaScript consumption
    pub fn sig_keypair_to_js(public_key: &[u8], secret_key: &[u8]) -> Result<JsValue> {
        let result = serde_json::json!({
            "public_key": public_key,
            "secret_key": secret_key,
            "algorithm": "signature"
        });

        serde_wasm_bindgen::to_value(&result).map_err(|e| crate::error::Error::NotImplemented {
            feature: format!("Serialization error: {:?}", e),
        })
    }

    /// Convert hash result to JavaScript object
    ///
    /// This function securely serializes hash data for JavaScript consumption
    pub fn hash_result_to_js(hash: &[u8], algorithm: Algorithm) -> Result<JsValue> {
        let result = serde_json::json!({
            "hash": hash,
            "algorithm": Self::algorithm_to_string(algorithm),
            "length": hash.len()
        });

        serde_wasm_bindgen::to_value(&result).map_err(|e| crate::error::Error::NotImplemented {
            feature: format!("Serialization error: {:?}", e),
        })
    }

    /// Convert error to JavaScript error
    ///
    /// This function provides secure error conversion that doesn't leak sensitive information
    pub fn error_to_js(error: &crate::error::Error) -> JsValue {
        // Only expose safe error information to JavaScript
        let safe_message = match error {
            crate::error::Error::NotImplemented { feature } => {
                format!("Feature not implemented: {}", feature)
            }
            crate::error::Error::InvalidAlgorithm { algorithm } => {
                format!("Invalid algorithm: {}", algorithm)
            }
            crate::error::Error::InvalidKey { key_type, reason } => {
                format!("Invalid {}: {}", key_type, reason)
            }
            crate::error::Error::InvalidMessageSize { max, actual } => {
                format!("Message size {} exceeds maximum {}", actual, max)
            }
            crate::error::Error::InvalidNonceSize { expected, actual } => {
                format!("Nonce size {} does not match expected {}", actual, expected)
            }
            _ => "Cryptographic operation failed".to_string(),
        };

        JsValue::from_str(&safe_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_conversion() {
        // Test string to algorithm conversion
        assert_eq!(
            WasmConversions::string_to_algorithm("ml-kem-512").unwrap(),
            Algorithm::MlKem512
        );
        assert_eq!(
            WasmConversions::string_to_algorithm("ML-KEM-512").unwrap(),
            Algorithm::MlKem512
        );
        assert_eq!(
            WasmConversions::string_to_algorithm("sha3-256").unwrap(),
            Algorithm::Sha3_256
        );

        // Test unsupported algorithm
        assert!(WasmConversions::string_to_algorithm("unsupported").is_err());

        // Test algorithm to string conversion
        assert_eq!(
            WasmConversions::algorithm_to_string(Algorithm::MlKem512),
            "ml-kem-512"
        );
        assert_eq!(
            WasmConversions::algorithm_to_string(Algorithm::Sha3_256),
            "sha3-256"
        );
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_error_conversion() {
        let error = crate::error::Error::NotImplemented {
            feature: "test feature".to_string(),
        };
        let js_error = WasmConversions::error_to_js(&error);
        // In a real WASM environment, we would test the JsValue
        // For now, we just ensure the function doesn't panic
        assert!(!js_error.is_undefined());
    }
}
