//! WASM Error Handling Module
//!
//! This module provides secure, consistent error handling for WASM bindings.
//! It ensures all WASM functions return Result<T, JsValue> consistently and
//! provides secure error conversion without information leakage.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::error::Error;

/// Convert Error to JsValue for WASM compatibility
///
/// This function provides secure error conversion that:
/// - Prevents information leakage through error messages
/// - Ensures consistent error handling across WASM bindings
/// - Maintains security by not exposing internal implementation details
#[cfg(feature = "wasm")]
pub fn error_to_js_value(error: Error) -> JsValue {
    // Security: Use generic error messages to prevent information leakage
    let message = match error {
        Error::InvalidAlgorithm { .. } => "Invalid algorithm specified",
        Error::InvalidKeySize { .. } => "Invalid key size",
        Error::InvalidMessageSize { .. } => "Invalid message size",
        Error::InvalidNonceSize { .. } => "Invalid nonce size",
        Error::InvalidSignatureSize { .. } => "Invalid signature",
        Error::InvalidCiphertextSize { .. } => "Invalid ciphertext",
        Error::InvalidPlaintextSize { .. } => "Invalid plaintext",
        Error::InvalidKeyFormat => "Invalid key material",
        Error::InvalidSecurityLevel { .. } => "Invalid security level",
        Error::NotImplemented { .. } => "Feature not implemented",
        Error::ProviderNotConfigured { .. } => "Provider not configured",
        Error::VerificationFailed { .. } => "Verification failed",
        Error::EncryptionFailed { .. } => "Encryption failed",
        Error::DecryptionFailed { .. } => "Decryption failed",
        Error::KeyGenerationFailed { .. } => "Key generation failed",
        Error::RandomGenerationFailed { .. } => "Random generation failed",
        Error::SigningFailed { .. } => "Signing failed",
        Error::MemoryAllocationFailed { .. } => "Memory allocation failed",
        Error::InternalError { .. } => "Internal error",
        Error::UnsupportedOperation { .. } => "Unsupported operation",
        Error::InvalidState { .. } => "Invalid context state",
        Error::PluginDependencyError { .. } => "Plugin dependency error",
        Error::PluginVersionIncompatible { .. } => "Plugin version incompatible",
        Error::InvalidKey { .. } => "Invalid key",
        Error::UnsupportedAlgorithm { .. } => "Unsupported algorithm",
        Error::AuthenticationFailed { .. } => "Authentication failed",
        Error::InvalidAssociatedDataSize { .. } => "Invalid associated data size",
        Error::InvalidTagSize { .. } => "Invalid tag size",
        Error::InvalidHashSize { .. } => "Invalid hash size",
        Error::InvalidRandomnessSize { .. } => "Invalid randomness size",
    };

    JsValue::from_str(message)
}

/// Helper function to convert Result<T, Error> to Result<T, JsValue>
///
/// This function provides a secure conversion that:
/// - Maintains type safety
/// - Ensures consistent error handling
/// - Prevents information leakage
#[cfg(feature = "wasm")]
pub fn convert_result<T>(result: Result<T, Error>) -> Result<T, JsValue> {
    result.map_err(error_to_js_value)
}

/// WASM-safe algorithm parsing that returns JsValue errors
///
/// This function provides secure algorithm parsing that:
/// - Validates input strings
/// - Returns consistent error types
/// - Prevents injection attacks
#[cfg(feature = "wasm")]
pub fn parse_algorithm_wasm(algorithm: &str) -> Result<crate::api::Algorithm, JsValue> {
    // Security: Validate input length to prevent DoS attacks
    if algorithm.len() > 64 {
        return Err(JsValue::from_str("Algorithm name too long"));
    }

    // Reject control characters; allow Unicode so names like `dawn-α-512` match
    // [`crate::wasm::conversions::WasmConversions::string_to_algorithm`].
    if algorithm.chars().any(|c| c.is_control()) {
        return Err(JsValue::from_str("Invalid algorithm name format"));
    }

    match crate::wasm::conversions::WasmConversions::string_to_algorithm(algorithm) {
        Ok(a) => Ok(a),
        Err(Error::UnsupportedAlgorithm { .. }) => Err(JsValue::from_str("Unsupported algorithm")),
        Err(_) => Err(JsValue::from_str("Invalid algorithm specified")),
    }
}

/// Secure WASM error handling macro
///
/// This macro provides secure error handling for WASM functions that:
/// - Ensures consistent error types
/// - Prevents information leakage
/// - Maintains security boundaries
#[cfg(feature = "wasm")]
#[macro_export]
macro_rules! wasm_result {
    ($expr:expr) => {
        match $expr {
            Ok(value) => Ok(value),
            Err(error) => Err($crate::wasm::error::error_to_js_value(error)),
        }
    };
}

/// Secure WASM validation macro
///
/// This macro provides secure validation for WASM inputs that:
/// - Validates input parameters
/// - Returns consistent error types
/// - Prevents injection attacks
#[cfg(feature = "wasm")]
#[macro_export]
macro_rules! wasm_validate {
    ($condition:expr, $error_msg:expr) => {
        if !$condition {
            return Err(JsValue::from_str($error_msg));
        }
    };
}

/// Secure WASM serialization helper
///
/// This function provides secure serialization that:
/// - Handles serialization errors gracefully
/// - Returns consistent error types
/// - Prevents information leakage
#[cfg(feature = "wasm")]
pub fn secure_serialize<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    match serde_wasm_bindgen::to_value(value) {
        Ok(js_value) => Ok(js_value),
        Err(_) => Err(JsValue::from_str("Serialization error")),
    }
}

/// Secure WASM deserialization helper
///
/// This function provides secure deserialization that:
/// - Handles deserialization errors gracefully
/// - Returns consistent error types
/// - Prevents information leakage
#[cfg(feature = "wasm")]
pub fn secure_deserialize<T: serde::de::DeserializeOwned>(value: &JsValue) -> Result<T, JsValue> {
    match serde_wasm_bindgen::from_value(value.clone()) {
        Ok(deserialized) => Ok(deserialized),
        Err(_) => Err(JsValue::from_str("Deserialization error")),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_error_conversion() {
        let error = Error::InvalidAlgorithm { algorithm: "test" };
        let js_error = error_to_js_value(error);
        assert!(js_error.is_string());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_algorithm_parsing() {
        assert!(parse_algorithm_wasm("sha3-256").is_ok());
        assert_eq!(
            parse_algorithm_wasm("mldsa65").unwrap(),
            crate::api::Algorithm::MlDsa65
        );
        assert_eq!(
            parse_algorithm_wasm("ML-DSA-65").unwrap(),
            crate::api::Algorithm::MlDsa65
        );
        assert_eq!(
            parse_algorithm_wasm("slh-dsa-shake256-128f-robust").unwrap(),
            crate::api::Algorithm::SlhDsaShake256128fRobust
        );
        assert_eq!(
            parse_algorithm_wasm("SlhDsaShake256128fRobust").unwrap(),
            crate::api::Algorithm::SlhDsaShake256128fRobust
        );
        assert!(parse_algorithm_wasm("invalid").is_err());
        assert!(parse_algorithm_wasm(&"a".repeat(100)).is_err());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_secure_serialization() {
        let value = serde_json::json!({"test": "value"});
        let result = secure_serialize(&value);
        assert!(result.is_ok());
    }
}
