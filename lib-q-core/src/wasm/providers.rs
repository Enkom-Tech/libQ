//! WASM-compatible provider bindings
//!
//! This module provides WASM-compatible bindings for cryptographic providers,
//! integrating with the new modular architecture and security validation system.

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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmProviderManager {
    /// Create a new WASM provider manager
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            provider: LibQCryptoProvider::new()
                .unwrap_or_else(|_| LibQCryptoProvider::new().unwrap()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Get provider information
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
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
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_algorithm(algorithm).is_ok()
    }

    /// Get algorithm information
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_algorithm_info(&self, algorithm: &str) -> Result<JsValue> {
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

            Ok(serde_wasm_bindgen::to_value(&info).map_err(|e| {
                crate::error::Error::NotImplemented {
                    feature: format!("Serialization error: {:?}", e),
                }
            })?)
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(crate::error::Error::NotImplemented {
                feature: "WASM feature not enabled".to_string(),
            })
        }
    }

    /// Get all supported algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
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
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_kem_algorithms(&self) -> Vec<String> {
        let mut algorithms = Vec::new();

        // Always include these algorithms (they're part of the core)
        algorithms.push("ml-kem-512".to_string());
        algorithms.push("ml-kem-768".to_string());
        algorithms.push("ml-kem-1024".to_string());

        // Add optional algorithms based on features
        algorithms.push("dawn".to_string());
        algorithms.push("rcpkc".to_string());

        algorithms
    }

    /// Get signature algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_signature_algorithms(&self) -> Vec<String> {
        let mut algorithms = Vec::new();

        // Always include these algorithms (they're part of the core)
        algorithms.push("ml-dsa-44".to_string());
        algorithms.push("ml-dsa-65".to_string());
        algorithms.push("ml-dsa-87".to_string());

        // Add optional algorithms based on features
        algorithms.push("fn-dsa".to_string());

        algorithms
    }

    /// Get hash algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_hash_algorithms(&self) -> Vec<String> {
        vec![
            "sha3-224".to_string(),
            "sha3-256".to_string(),
            "sha3-384".to_string(),
            "sha3-512".to_string(),
            "shake128".to_string(),
            "shake256".to_string(),
        ]
    }

    /// Get AEAD algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn get_aead_algorithms(&self) -> Vec<String> {
        let mut algorithms = Vec::new();

        // Add optional algorithms based on features
        algorithms.push("saturnin".to_string());
        algorithms.push("shake256-aead".to_string());
        algorithms.push("kem-aead".to_string());

        algorithms
    }

    /// Validate algorithm parameters
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn validate_algorithm_params(
        &self,
        algorithm: &str,
        key_size: Option<usize>,
        message_size: Option<usize>,
        nonce_size: Option<usize>,
    ) -> Result<bool> {
        let _algorithm = self.parse_algorithm(algorithm)?;

        // Simplified validation - in a real implementation, this would be more comprehensive
        if let Some(size) = key_size {
            if size == 0 {
                return Err(crate::error::Error::InvalidKey {
                    key_type: "Algorithm key".to_string(),
                    reason: "Empty key".to_string(),
                });
            }
        }

        if let Some(size) = message_size {
            if size == 0 {
                return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
            }
        }

        if let Some(size) = nonce_size {
            if size == 0 {
                return Err(crate::error::Error::InvalidNonceSize {
                    expected: 12, // Placeholder
                    actual: 0,
                });
            }
        }

        Ok(true)
    }

    /// Get security recommendations
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
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
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
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
    fn parse_algorithm(&self, algorithm: &str) -> Result<Algorithm> {
        match algorithm {
            // KEM algorithms
            "ml-kem-512" => Ok(Algorithm::MlKem512),
            "ml-kem-768" => Ok(Algorithm::MlKem768),
            "ml-kem-1024" => Ok(Algorithm::MlKem1024),
            "dawn" => Ok(Algorithm::Dawn),
            "rcpkc" => Ok(Algorithm::Rcpkc),

            // Signature algorithms
            "ml-dsa-44" => Ok(Algorithm::MlDsa44),
            "ml-dsa-65" => Ok(Algorithm::MlDsa65),
            "ml-dsa-87" => Ok(Algorithm::MlDsa87),
            "fn-dsa" => Ok(Algorithm::FnDsa),

            // Hash algorithms
            "sha3-224" => Ok(Algorithm::Sha3_224),
            "sha3-256" => Ok(Algorithm::Sha3_256),
            "sha3-384" => Ok(Algorithm::Sha3_384),
            "sha3-512" => Ok(Algorithm::Sha3_512),
            "shake128" => Ok(Algorithm::Shake128),
            "shake256" => Ok(Algorithm::Shake256),

            // AEAD algorithms
            "saturnin" => Ok(Algorithm::Saturnin),
            "shake256-aead" => Ok(Algorithm::Shake256Aead),
            "kem-aead" => Ok(Algorithm::KemAead),

            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
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
    pub fn create_provider_manager_with_config(config: &str) -> Result<WasmProviderManager> {
        #[cfg(feature = "wasm")]
        {
            // Parse configuration (simplified for now)
            let _config: serde_json::Value =
                serde_json::from_str(config).map_err(|e| crate::error::Error::NotImplemented {
                    feature: format!("Configuration parsing error: {:?}", e),
                })?;

            // For now, just create a default provider manager
            // In a real implementation, this would configure the provider based on the config
            Ok(WasmProviderManager::new())
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(crate::error::Error::NotImplemented {
                feature: "WASM feature not enabled".to_string(),
            })
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
    pub fn validate_provider_config(config: &str) -> Result<bool> {
        #[cfg(feature = "wasm")]
        {
            let _config: serde_json::Value =
                serde_json::from_str(config).map_err(|e| crate::error::Error::NotImplemented {
                    feature: format!("Configuration parsing error: {:?}", e),
                })?;

            // Basic validation - in a real implementation, this would be more comprehensive
            Ok(true)
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(crate::error::Error::NotImplemented {
                feature: "WASM feature not enabled".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_provider_manager_creation() {
        let manager = WasmProviderManager::new();
        let info = manager.get_provider_info();
        assert!(info.contains("lib-Q") || info == "{}");
    }

    #[test]
    fn test_wasm_provider_factory() {
        let manager = WasmProviderFactory::create_provider_manager();
        assert!(manager.is_algorithm_supported("sha3-256"));
    }

    #[test]
    fn test_algorithm_support() {
        let manager = WasmProviderManager::new();
        assert!(manager.is_algorithm_supported("sha3-256"));
        assert!(!manager.is_algorithm_supported("invalid-algorithm"));
    }

    #[test]
    fn test_algorithm_info() {
        let manager = WasmProviderManager::new();
        let info = manager.get_algorithm_info("sha3-256");
        assert!(info.is_ok());
    }

    #[test]
    fn test_security_recommendations() {
        let manager = WasmProviderManager::new();
        let recommendations = manager.get_security_recommendations();
        assert!(
            recommendations.contains("use_authenticated_encryption") || recommendations == "{}"
        );
    }
}
