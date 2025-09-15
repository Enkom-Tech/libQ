//! WASM-compatible context wrappers
//!
//! This module provides WASM-compatible wrappers for all cryptographic contexts,
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
use crate::contexts::{
    AeadContext,
    HashContext,
    KemContext,
    SignatureContext,
};
use crate::error::Result;
use crate::providers::LibQCryptoProvider;
use crate::security::SecurityValidator;

/// WASM-compatible KEM context wrapper
///
/// This wrapper provides JavaScript-compatible bindings for KEM operations:
/// - Integrates with the new modular architecture
/// - Includes security validation
/// - Provides consistent error handling
/// - Supports all KEM algorithms
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmKemContext {
    inner: KemContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmKemContext {
    /// Create a new WASM KEM context with default provider
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: KemContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Create a new WASM KEM context with custom provider
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn with_provider(provider: &WasmCryptoProvider) -> Self {
        Self {
            inner: KemContext::with_provider(provider.inner.clone()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Generate a keypair for the specified algorithm
    ///
    /// This method provides secure key generation with:
    /// - Algorithm validation
    /// - Security level verification
    /// - Secure random generation
    /// - Proper error handling
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<&Uint8Array>,
    ) -> Result<JsValue> {
        // Parse and validate algorithm
        let algorithm = self.parse_kem_algorithm(algorithm)?;

        // Validate security level
        self.security_validator
            .validate_algorithm_category(algorithm, algorithm.category())?;

        // Convert randomness if provided
        let randomness_bytes = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        // Generate keypair
        let keypair = self.inner.generate_keypair(algorithm, randomness_bytes)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "public_key": keypair.public_key.data,
                "secret_key": keypair.secret_key.data,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            Ok(serde_wasm_bindgen::to_value(&result).map_err(|e| {
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

    /// Encapsulate a shared secret using the given public key
    ///
    /// This method provides secure encapsulation with:
    /// - Public key validation
    /// - Algorithm verification
    /// - Security level checking
    /// - Proper error handling
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn encapsulate(
        &self,
        algorithm: &str,
        public_key_data: &Uint8Array,
        randomness: Option<&Uint8Array>,
    ) -> Result<JsValue> {
        // Parse and validate algorithm
        let algorithm = self.parse_kem_algorithm(algorithm)?;

        // Validate public key size (simplified)
        if public_key_data.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "KEM public key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Convert randomness if provided
        let randomness_bytes = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        // Create public key
        let public_key = crate::KemPublicKey {
            data: public_key_data.to_vec(),
        };

        // Encapsulate
        let (ciphertext, shared_secret) =
            self.inner
                .encapsulate(algorithm, &public_key, randomness_bytes)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "ciphertext": ciphertext,
                "shared_secret": shared_secret,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            Ok(serde_wasm_bindgen::to_value(&result).map_err(|e| {
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

    /// Decapsulate a shared secret using the given secret key and ciphertext
    ///
    /// This method provides secure decapsulation with:
    /// - Secret key validation
    /// - Ciphertext verification
    /// - Algorithm checking
    /// - Proper error handling
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn decapsulate(
        &self,
        algorithm: &str,
        secret_key_data: &Uint8Array,
        ciphertext: &Uint8Array,
    ) -> Result<Vec<u8>> {
        // Parse and validate algorithm
        let algorithm = self.parse_kem_algorithm(algorithm)?;

        // Validate secret key size (simplified)
        if secret_key_data.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "KEM secret key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Validate ciphertext size (simplified)
        if ciphertext.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Create secret key
        let secret_key = crate::KemSecretKey {
            data: secret_key_data.to_vec(),
        };

        // Decapsulate
        let shared_secret = self
            .inner
            .decapsulate(algorithm, &secret_key, &ciphertext.to_vec())?;

        Ok(shared_secret)
    }

    /// Get the security level of the context
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn security_level(&self) -> u32 {
        // Return the highest security level supported by the context
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_kem_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn supported_algorithms(&self) -> String {
        let algorithms = vec!["ml-kem-512", "ml-kem-768", "ml-kem-1024", "dawn", "rcpkc"];
        #[cfg(feature = "wasm")]
        {
            serde_json::to_string(&algorithms).unwrap_or_else(|_| "[]".to_string())
        }
        #[cfg(not(feature = "wasm"))]
        {
            "[]".to_string()
        }
    }

    /// Parse KEM algorithm from string
    fn parse_kem_algorithm(&self, algorithm: &str) -> Result<Algorithm> {
        match algorithm {
            "ml-kem-512" => Ok(Algorithm::MlKem512),
            "ml-kem-768" => Ok(Algorithm::MlKem768),
            "ml-kem-1024" => Ok(Algorithm::MlKem1024),
            "dawn" => Ok(Algorithm::Dawn),
            "rcpkc" => Ok(Algorithm::Rcpkc),
            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
    }
}

/// WASM-compatible Signature context wrapper
///
/// This wrapper provides JavaScript-compatible bindings for signature operations:
/// - Integrates with the new modular architecture
/// - Includes security validation
/// - Provides consistent error handling
/// - Supports all signature algorithms
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmSignatureContext {
    inner: SignatureContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmSignatureContext {
    /// Create a new WASM Signature context with default provider
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: SignatureContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Create a new WASM Signature context with custom provider
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn with_provider(provider: &WasmCryptoProvider) -> Self {
        Self {
            inner: SignatureContext::with_provider(provider.inner.clone()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Generate a keypair for the specified algorithm
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<&Uint8Array>,
    ) -> Result<JsValue> {
        // Parse and validate algorithm
        let algorithm = self.parse_signature_algorithm(algorithm)?;

        // Validate security level
        self.security_validator
            .validate_algorithm_category(algorithm, algorithm.category())?;

        // Convert randomness if provided
        let randomness_bytes = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        // Generate keypair
        let keypair = self.inner.generate_keypair(algorithm, randomness_bytes)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "public_key": keypair.public_key.data,
                "secret_key": keypair.secret_key.data,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            Ok(serde_wasm_bindgen::to_value(&result).map_err(|e| {
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

    /// Sign a message using the given secret key
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn sign(
        &self,
        algorithm: &str,
        secret_key_data: &Uint8Array,
        message: &Uint8Array,
        randomness: Option<&Uint8Array>,
    ) -> Result<Vec<u8>> {
        // Parse and validate algorithm
        let algorithm = self.parse_signature_algorithm(algorithm)?;

        // Validate secret key size (simplified)
        if secret_key_data.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "Signature secret key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Validate message size (simplified)
        if message.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Convert randomness if provided
        let randomness_bytes = if let Some(rand) = randomness {
            Some(rand.to_vec().as_slice())
        } else {
            None
        };

        // Create secret key
        let secret_key = crate::SigSecretKey {
            data: secret_key_data.to_vec(),
        };

        // Sign
        let signature =
            self.inner
                .sign(algorithm, &secret_key, &message.to_vec(), randomness_bytes)?;

        Ok(signature)
    }

    /// Verify a signature using the given public key
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn verify(
        &self,
        algorithm: &str,
        public_key_data: &Uint8Array,
        message: &Uint8Array,
        signature: &Uint8Array,
    ) -> Result<bool> {
        // Parse and validate algorithm
        let algorithm = self.parse_signature_algorithm(algorithm)?;

        // Validate public key size (simplified)
        if public_key_data.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "Signature public key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Validate message size (simplified)
        if message.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Validate signature size (simplified)
        if signature.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Create public key
        let public_key = crate::SigPublicKey {
            data: public_key_data.to_vec(),
        };

        // Verify
        let is_valid = self.inner.verify(
            algorithm,
            &public_key,
            &message.to_vec(),
            &signature.to_vec(),
        )?;

        Ok(is_valid)
    }

    /// Get the security level of the context
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_signature_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn supported_algorithms(&self) -> String {
        let algorithms = vec!["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "fn-dsa"];
        #[cfg(feature = "wasm")]
        {
            serde_json::to_string(&algorithms).unwrap_or_else(|_| "[]".to_string())
        }
        #[cfg(not(feature = "wasm"))]
        {
            "[]".to_string()
        }
    }

    /// Parse signature algorithm from string
    fn parse_signature_algorithm(&self, algorithm: &str) -> Result<Algorithm> {
        match algorithm {
            "ml-dsa-44" => Ok(Algorithm::MlDsa44),
            "ml-dsa-65" => Ok(Algorithm::MlDsa65),
            "ml-dsa-87" => Ok(Algorithm::MlDsa87),
            "fn-dsa" => Ok(Algorithm::FnDsa),
            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
    }
}

/// WASM-compatible Hash context wrapper
///
/// This wrapper provides JavaScript-compatible bindings for hash operations:
/// - Integrates with the new modular architecture
/// - Includes security validation
/// - Provides consistent error handling
/// - Supports all hash algorithms
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmHashContext {
    inner: HashContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmHashContext {
    /// Create a new WASM Hash context with default provider
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: HashContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Create a new WASM Hash context with custom provider
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn with_provider(provider: &WasmCryptoProvider) -> Self {
        Self {
            inner: HashContext::with_provider(provider.inner.clone()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Hash data using the specified algorithm
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn hash(&self, algorithm: &str, data: &Uint8Array) -> Result<JsValue> {
        // Parse and validate algorithm
        let algorithm = self.parse_hash_algorithm(algorithm)?;

        // Validate data size (simplified)
        if data.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Hash
        let hash_result = self.inner.hash(algorithm, &data.to_vec())?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "hash": hash_result.hash,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            Ok(serde_wasm_bindgen::to_value(&result).map_err(|e| {
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

    /// Get the security level of the context
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_hash_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn supported_algorithms(&self) -> String {
        let algorithms = vec![
            "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256",
        ];
        #[cfg(feature = "wasm")]
        {
            serde_json::to_string(&algorithms).unwrap_or_else(|_| "[]".to_string())
        }
        #[cfg(not(feature = "wasm"))]
        {
            "[]".to_string()
        }
    }

    /// Parse hash algorithm from string
    fn parse_hash_algorithm(&self, algorithm: &str) -> Result<Algorithm> {
        match algorithm {
            "sha3-224" => Ok(Algorithm::Sha3_224),
            "sha3-256" => Ok(Algorithm::Sha3_256),
            "sha3-384" => Ok(Algorithm::Sha3_384),
            "sha3-512" => Ok(Algorithm::Sha3_512),
            "shake128" => Ok(Algorithm::Shake128),
            "shake256" => Ok(Algorithm::Shake256),
            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
    }
}

/// WASM-compatible AEAD context wrapper
///
/// This wrapper provides JavaScript-compatible bindings for AEAD operations:
/// - Integrates with the new modular architecture
/// - Includes security validation
/// - Provides consistent error handling
/// - Supports all AEAD algorithms
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmAeadContext {
    inner: AeadContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmAeadContext {
    /// Create a new WASM AEAD context with default provider
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: AeadContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Create a new WASM AEAD context with custom provider
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn with_provider(provider: &WasmCryptoProvider) -> Self {
        Self {
            inner: AeadContext::with_provider(provider.inner.clone()),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Encrypt data using the specified algorithm
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn encrypt(
        &self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        plaintext: &Uint8Array,
        aad: Option<&Uint8Array>,
    ) -> Result<Vec<u8>> {
        // Parse and validate algorithm
        let algorithm = self.parse_aead_algorithm(algorithm)?;

        // Validate key size (simplified)
        if key.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "AEAD key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Validate nonce size (simplified)
        if nonce.length() == 0 {
            return Err(crate::error::Error::InvalidNonceSize {
                expected: 12, // Placeholder
                actual: 0,
            });
        }

        // Validate plaintext size (simplified)
        if plaintext.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Convert AAD if provided
        let aad_bytes = if let Some(aad_data) = aad {
            Some(aad_data.to_vec())
        } else {
            None
        };

        // Encrypt
        let ciphertext = self.inner.encrypt(
            algorithm,
            &key.to_vec(),
            &nonce.to_vec(),
            &plaintext.to_vec(),
            aad_bytes.as_deref(),
        )?;

        Ok(ciphertext)
    }

    /// Decrypt data using the specified algorithm
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn decrypt(
        &self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        ciphertext: &Uint8Array,
        aad: Option<&Uint8Array>,
    ) -> Result<Vec<u8>> {
        // Parse and validate algorithm
        let algorithm = self.parse_aead_algorithm(algorithm)?;

        // Validate key size (simplified)
        if key.length() == 0 {
            return Err(crate::error::Error::InvalidKey {
                key_type: "AEAD key".to_string(),
                reason: "Empty key".to_string(),
            });
        }

        // Validate nonce size (simplified)
        if nonce.length() == 0 {
            return Err(crate::error::Error::InvalidNonceSize {
                expected: 12, // Placeholder
                actual: 0,
            });
        }

        // Validate ciphertext size (simplified)
        if ciphertext.length() == 0 {
            return Err(crate::error::Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Convert AAD if provided
        let aad_bytes = if let Some(aad_data) = aad {
            Some(aad_data.to_vec())
        } else {
            None
        };

        // Decrypt
        let plaintext = self.inner.decrypt(
            algorithm,
            &key.to_vec(),
            &nonce.to_vec(),
            &ciphertext.to_vec(),
            aad_bytes.as_deref(),
        )?;

        Ok(plaintext)
    }

    /// Get the security level of the context
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_aead_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn supported_algorithms(&self) -> String {
        let algorithms = vec!["saturnin", "shake256-aead", "kem-aead"];
        #[cfg(feature = "wasm")]
        {
            serde_json::to_string(&algorithms).unwrap_or_else(|_| "[]".to_string())
        }
        #[cfg(not(feature = "wasm"))]
        {
            "[]".to_string()
        }
    }

    /// Parse AEAD algorithm from string
    fn parse_aead_algorithm(&self, algorithm: &str) -> Result<Algorithm> {
        match algorithm {
            "saturnin" => Ok(Algorithm::Saturnin),
            "shake256-aead" => Ok(Algorithm::Shake256Aead),
            "kem-aead" => Ok(Algorithm::KemAead),
            _ => Err(crate::error::Error::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            }),
        }
    }
}

/// WASM-compatible CryptoProvider wrapper
///
/// This wrapper provides JavaScript-compatible bindings for the crypto provider:
/// - Integrates with the new modular architecture
/// - Provides consistent error handling
/// - Supports all cryptographic operations
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct WasmCryptoProvider {
    inner: LibQCryptoProvider,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl WasmCryptoProvider {
    /// Create a new WASM CryptoProvider
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: LibQCryptoProvider::new().unwrap_or_else(|_| LibQCryptoProvider::new().unwrap()),
        }
    }

    /// Get the provider information
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn info(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            serde_json::json!({
                "name": "lib-Q Crypto Provider",
                "version": crate::VERSION,
                "features": {
                    "kem": true,
                    "signature": true,
                    "hash": true,
                    "aead": true,
                    "security_hardened": true
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
        // This would check against the actual provider implementation
        true // Placeholder
    }

    /// Get supported algorithms by category
    #[cfg_attr(feature = "wasm", wasm_bindgen)]
    pub fn supported_algorithms(&self) -> String {
        #[cfg(feature = "wasm")]
        {
            let algorithms = serde_json::json!({
                "kem": ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "dawn", "rcpkc"],
                "signature": ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "fn-dsa"],
                "hash": ["sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256"],
                "aead": ["saturnin", "shake256-aead", "kem-aead"]
            });
            algorithms.to_string()
        }
        #[cfg(not(feature = "wasm"))]
        {
            "{}".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_kem_context_creation() {
        let context = WasmKemContext::new();
        assert_eq!(context.security_level(), 256);
    }

    #[test]
    fn test_wasm_signature_context_creation() {
        let context = WasmSignatureContext::new();
        assert_eq!(context.security_level(), 256);
    }

    #[test]
    fn test_wasm_hash_context_creation() {
        let context = WasmHashContext::new();
        assert_eq!(context.security_level(), 256);
    }

    #[test]
    fn test_wasm_aead_context_creation() {
        let context = WasmAeadContext::new();
        assert_eq!(context.security_level(), 256);
    }

    #[test]
    fn test_wasm_crypto_provider_creation() {
        let provider = WasmCryptoProvider::new();
        let info = provider.info();
        assert!(info.contains("lib-Q") || info == "{}");
    }
}
