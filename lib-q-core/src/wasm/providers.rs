//! WASM-compatible provider bindings
//!
//! This module provides WASM-compatible bindings for cryptographic providers,
//! integrating with the new modular architecture and security validation system.

#[cfg(feature = "wasm")]
extern crate alloc;
#[cfg(feature = "wasm")]
use alloc::{
    string::{
        String,
        ToString,
    },
    vec::Vec,
};

#[cfg(feature = "wasm")]
// use js_sys::Uint8Array;
use serde_json;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::api::{
    Algorithm,
    CryptoProvider,
};
// use crate::error::Result;
use crate::providers::LibQCryptoProvider;
use crate::security::SecurityValidator;

/// WASM-compatible provider manager
///
/// This manager provides JavaScript-compatible bindings for provider operations:
/// - Integrates with the new modular architecture
/// - Includes security validation
/// - Provides consistent error handling
/// - Supports all provider operations
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmProviderManager {
    provider: LibQCryptoProvider,
    security_validator: SecurityValidator,
}

impl WasmProviderManager {
    /// Create a new WASM provider manager
    pub fn new() -> WasmProviderManager {
        WasmProviderManager {
            provider: LibQCryptoProvider::new()
                .unwrap_or_else(|_| LibQCryptoProvider::new().unwrap()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }
}

impl Default for WasmProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmProviderManager {
    /// Get provider information
    pub fn get_provider_info(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            serde_json::json!({
                "name": "lib-Q Crypto Provider",
                "version": crate::VERSION,
                "description": "Post-Quantum Cryptography Provider",
                "features": {
                    "kem": true,
                    "signature": true,
                    "hash": true,
                    "aead": true,
                    "security_hardened": true,
                    "post_quantum": true
                },
                "security_levels": [128, 192, 256],
                "algorithms": {
                    "kem": self.get_kem_algorithms(),
                    "signature": self.get_signature_algorithms(),
                    "hash": self.get_hash_algorithms(),
                    "aead": self.get_aead_algorithms()
                }
            })
            .to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }

    /// Check if an algorithm is supported
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        // First check if it's a valid algorithm name
        let algorithm = match self.parse_algorithm(algorithm) {
            Ok(alg) => alg,
            Err(_) => return false,
        };

        // Then check if the provider actually supports this algorithm
        match algorithm.category() {
            crate::api::AlgorithmCategory::Kem => self.provider.kem().is_some(),
            crate::api::AlgorithmCategory::Signature => self.provider.signature().is_some(),
            crate::api::AlgorithmCategory::Hash => self.provider.hash().is_some(),
            crate::api::AlgorithmCategory::Aead => self.provider.aead().is_some(),
        }
    }

    /// Get algorithm information
    pub fn get_algorithm_info(&self, algorithm: &str) -> Result<JsValue, JsValue> {
        let algorithm = self.parse_algorithm(algorithm)?;

        #[cfg(feature = "wasm")]
        {
            let info = serde_json::json!({
                "name": algorithm.to_string(),
                "category": algorithm.category().to_string(),
                "security_level": 256, // Placeholder
                "key_sizes": {
                    "public_key": 1024, // Placeholder
                    "secret_key": 1024, // Placeholder
                    "signature": 1024, // Placeholder
                    "nonce": 12, // Placeholder
                    "key": 32 // Placeholder
                },
                "message_limits": {
                    "max_size": 1024 * 1024 // Placeholder
                },
                "features": {
                    "kem": algorithm.category() == crate::api::AlgorithmCategory::Kem,
                    "signature": algorithm.category() == crate::api::AlgorithmCategory::Signature,
                    "hash": algorithm.category() == crate::api::AlgorithmCategory::Hash,
                    "aead": algorithm.category() == crate::api::AlgorithmCategory::Aead
                }
            });

            match serde_wasm_bindgen::to_value(&info) {
                Ok(value) => Ok(value),
                Err(_) => Err(JsValue::from_str("Serialization error")),
            }
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Get all supported algorithms
    pub fn get_all_algorithms(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            let algorithms = serde_json::json!({
                "kem": self.get_kem_algorithms(),
                "signature": self.get_signature_algorithms(),
                "hash": self.get_hash_algorithms(),
                "aead": self.get_aead_algorithms()
            });
            algorithms.to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }

    /// Get KEM algorithms
    pub fn get_kem_algorithms(&self) -> Vec<String> {
        #[allow(unused_mut)] // mut needed when feature flags are enabled
        let mut algorithms = alloc::vec![
            "ml-kem-512".to_string(),
            "ml-kem-768".to_string(),
            "ml-kem-1024".to_string(),
        ];

        // Add optional algorithms based on features
        #[cfg(feature = "dawn")]
        {
            algorithms.push("dawn-α-512".to_string());
            algorithms.push("dawn-β-512".to_string());
            algorithms.push("dawn-α-1024".to_string());
            algorithms.push("dawn-β-1024".to_string());
        }

        algorithms
    }

    /// Get signature algorithms
    pub fn get_signature_algorithms(&self) -> Vec<String> {
        crate::wasm::conversions::WASM_SIGNATURE_ALGORITHM_IDS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// Get hash algorithms
    pub fn get_hash_algorithms(&self) -> Vec<String> {
        alloc::vec![
            "sha3-224".to_string(),
            "sha3-256".to_string(),
            "sha3-384".to_string(),
            "sha3-512".to_string(),
            "shake128".to_string(),
            "shake256".to_string(),
        ]
    }

    /// Get AEAD algorithms
    pub fn get_aead_algorithms(&self) -> Vec<String> {
        let algorithms = alloc::vec![
            "saturnin".to_string(),
            "shake256-aead".to_string(),
            "kem-aead".to_string(),
        ];

        algorithms
    }

    /// Validate algorithm parameters
    pub fn validate_algorithm_params(
        &self,
        algorithm: &str,
        key_size: Option<usize>,
        message_size: Option<usize>,
        nonce_size: Option<usize>,
    ) -> Result<bool, JsValue> {
        let algorithm = self.parse_algorithm(algorithm)?;

        // Use security validator for comprehensive validation
        if let Some(size) = key_size {
            if size == 0 {
                return Err(JsValue::from_str("Invalid algorithm key: empty key"));
            }
            // Validate key size against algorithm requirements
            let test_key = (0..size).map(|_| 0u8).collect::<Vec<u8>>();
            self.security_validator
                .validate_key_size(algorithm, &test_key, true)
                .map_err(crate::wasm::error::error_to_js_value)?;
        }

        if let Some(size) = message_size {
            if size == 0 {
                return Err(JsValue::from_str("Invalid message size: empty data"));
            }
            // Validate message size
            let test_message = (0..size).map(|_| 0u8).collect::<Vec<u8>>();
            self.security_validator
                .validate_message(&test_message)
                .map_err(crate::wasm::error::error_to_js_value)?;
        }

        if let Some(size) = nonce_size {
            if size == 0 {
                return Err(JsValue::from_str("Invalid nonce size: empty nonce"));
            }
            // Validate nonce size
            let test_nonce = (0..size).map(|_| 0u8).collect::<Vec<u8>>();
            self.security_validator
                .validate_nonce(&test_nonce)
                .map_err(crate::wasm::error::error_to_js_value)?;
        }

        Ok(true)
    }

    /// Get security recommendations
    pub fn get_security_recommendations(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            serde_json::json!({
                "general": {
                    "use_authenticated_encryption": true,
                    "validate_all_inputs": true,
                    "use_secure_random": true,
                    "protect_secret_keys": true,
                    "rotate_keys_regularly": true
                },
                "kem": {
                    "recommended_algorithms": ["ml-kem-768", "ml-kem-1024"],
                    "key_rotation": "Every 90 days",
                    "security_level": "Minimum 192-bit"
                },
                "signature": {
                    "recommended_algorithms": ["ml-dsa-65", "ml-dsa-87"],
                    "key_rotation": "Every 90 days",
                    "security_level": "Minimum 192-bit"
                },
                "hash": {
                    "recommended_algorithms": ["sha3-256", "sha3-384"],
                    "security_level": "Minimum 256-bit"
                },
                "aead": {
                    "recommended_algorithms": ["saturnin", "shake256-aead"],
                    "nonce_requirements": "Unique per key",
                    "security_level": "Minimum 256-bit"
                }
            })
            .to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }

    /// Get performance benchmarks
    pub fn get_performance_benchmarks(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            serde_json::json!({
                "note": "Performance benchmarks are environment-dependent",
                "recommendations": {
                    "kem": {
                        "fastest": "ml-kem-512",
                        "most_secure": "ml-kem-1024",
                        "balanced": "ml-kem-768"
                    },
                    "signature": {
                        "fastest": "ml-dsa-44",
                        "most_secure": "ml-dsa-87",
                        "balanced": "ml-dsa-65"
                    },
                    "hash": {
                        "fastest": "sha3-224",
                        "most_secure": "sha3-512",
                        "balanced": "sha3-256"
                    }
                }
            })
            .to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }

    /// Parse algorithm from string
    fn parse_algorithm(&self, algorithm: &str) -> Result<Algorithm, crate::error::Error> {
        crate::wasm::error::parse_algorithm_wasm(algorithm).map_err(|_| {
            crate::error::Error::InvalidAlgorithm {
                algorithm: "Invalid algorithm name",
            }
        })
    }
}

/// WASM-compatible provider factory
///
/// This factory provides JavaScript-compatible bindings for creating providers:
/// - Integrates with the new modular architecture
/// - Provides consistent error handling
/// - Supports all provider creation operations
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmProviderFactory;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmProviderFactory {
    /// Create a new provider manager
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn create_provider_manager() -> WasmProviderManager {
        WasmProviderManager::new()
    }

    /// Create a provider manager with specific configuration
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn create_provider_manager_with_config(
        config: &str,
    ) -> Result<WasmProviderManager, JsValue> {
        #[cfg(feature = "wasm")]
        {
            // Parse configuration (simplified for now)
            let _config: serde_json::Value = match serde_json::from_str(config) {
                Ok(config) => config,
                Err(_) => {
                    return Err(JsValue::from_str("Configuration parsing error"));
                }
            };

            // For now, just create a default provider manager
            // In a real implementation, this would configure the provider based on the config
            Ok(WasmProviderManager::new())
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Get available provider types
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_available_providers() -> String {
        #[cfg(feature = "wasm")]
        {
            serde_json::json!({
                "providers": [
                    {
                        "name": "lib-q-crypto",
                        "description": "Default lib-Q cryptographic provider",
                        "features": ["kem", "signature", "hash", "aead"],
                        "security_levels": [128, 192, 256]
                    }
                ]
            })
            .to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }

    /// Validate provider configuration
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn validate_provider_config(config: &str) -> Result<bool, JsValue> {
        #[cfg(feature = "wasm")]
        {
            let _config: serde_json::Value = match serde_json::from_str(config) {
                Ok(config) => config,
                Err(_) => {
                    return Err(JsValue::from_str("Configuration parsing error"));
                }
            };

            // Basic validation - in a real implementation, this would be more comprehensive
            Ok(true)
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_provider_manager_creation() {
        let manager = WasmProviderManager::new();
        let info = manager.get_provider_info();
        assert!(info.contains("lib-Q") || info == "{}");
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_provider_factory() {
        let manager = WasmProviderFactory::create_provider_manager();
        assert!(manager.is_algorithm_supported("sha3-256"));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_algorithm_support() {
        let manager = WasmProviderManager::new();
        assert!(manager.is_algorithm_supported("sha3-256"));
        assert!(!manager.is_algorithm_supported("invalid-algorithm"));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_algorithm_info() {
        let manager = WasmProviderManager::new();
        let info = manager.get_algorithm_info("sha3-256");
        assert!(info.is_ok());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_security_recommendations() {
        let manager = WasmProviderManager::new();
        let recommendations = manager.get_security_recommendations();
        assert!(
            recommendations.contains("use_authenticated_encryption") || recommendations == "{}"
        );
    }
}
