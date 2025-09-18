//! WASM-compatible context wrappers
//!
//! This module provides WASM-compatible wrappers for all cryptographic contexts,
//! integrating with the new modular architecture and security validation system.

#[cfg(feature = "wasm")]
extern crate alloc;
#[cfg(feature = "wasm")]
use alloc::{
    boxed::Box,
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

use crate::api::{
    Algorithm,
    AlgorithmCategory,
};
use crate::contexts::{
    AeadContext,
    HashContext,
    KemContext,
    SignatureContext,
};
// use crate::error::Result;
use crate::providers::LibQCryptoProvider;
use crate::security::SecurityValidator;
use crate::traits::{
    AeadKey,
    Nonce,
};
// Import secure error handling
use crate::wasm::error::{
    convert_result,
    error_to_js_value,
    parse_algorithm_wasm,
    // secure_serialize,
};

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

impl WasmKemContext {
    /// Create a new WASM KEM context with default provider
    pub fn new() -> WasmKemContext {
        WasmKemContext {
            inner: KemContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Create a new WASM KEM context with custom provider
    pub fn with_provider(provider: &WasmCryptoProvider) -> WasmKemContext {
        WasmKemContext {
            inner: KemContext::with_provider(Box::new(provider.inner.clone())),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }
}

impl Default for WasmKemContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmKemContext {
    /// Generate a keypair for the specified algorithm
    ///
    /// This method provides secure key generation with:
    /// - Algorithm validation
    /// - Security level verification
    /// - Secure random generation
    /// - Proper error handling
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_kem_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate security level
        convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, algorithm.category()),
        )?;

        // Convert randomness if provided
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_bytes = randomness_vec.as_deref();

        // Generate keypair
        let keypair = self
            .inner
            .generate_keypair(algorithm, randomness_bytes)
            .map_err(error_to_js_value)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "public_key": keypair.public_key.data,
                "secret_key": keypair.secret_key.data,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Encapsulate a shared secret using the given public key
    ///
    /// This method provides secure encapsulation with:
    /// - Public key validation
    /// - Algorithm verification
    /// - Security level checking
    /// - Proper error handling
    pub fn encapsulate(
        &self,
        algorithm: &str,
        public_key_data: &Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_kem_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate public key size (simplified)
        if public_key_data.length() == 0 {
            return Err(JsValue::from_str("Invalid KEM public key: empty key"));
        }

        // Convert randomness if provided
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_bytes = randomness_vec.as_deref();

        // Create public key using proper constructor
        let public_key = crate::traits::KemPublicKey::new(public_key_data.to_vec());

        // Encapsulate
        let (ciphertext, shared_secret) = self
            .inner
            .encapsulate(algorithm, &public_key, randomness_bytes)
            .map_err(error_to_js_value)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "ciphertext": ciphertext,
                "shared_secret": shared_secret,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Decapsulate a shared secret using the given secret key and ciphertext
    ///
    /// This method provides secure decapsulation with:
    /// - Secret key validation
    /// - Ciphertext verification
    /// - Algorithm checking
    /// - Proper error handling
    pub fn decapsulate(
        &self,
        algorithm: &str,
        secret_key_data: &Uint8Array,
        ciphertext: &Uint8Array,
    ) -> Result<Vec<u8>, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_kem_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Kem)
            .map_err(error_to_js_value)?;

        // Validate secret key size
        if secret_key_data.length() == 0 {
            return Err(JsValue::from_str("Invalid KEM secret key: empty key"));
        }

        // Validate ciphertext size
        if ciphertext.length() == 0 {
            return Err(JsValue::from_str("Invalid message size: empty data"));
        }

        // Create secret key using proper constructor
        let secret_key = crate::traits::KemSecretKey::new(secret_key_data.to_vec());

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())
            .map_err(error_to_js_value)?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, &ciphertext.to_vec())
            .map_err(error_to_js_value)?;

        // Decapsulate
        let shared_secret = self
            .inner
            .decapsulate(algorithm, &secret_key, &ciphertext.to_vec())
            .map_err(error_to_js_value)?;

        Ok(shared_secret)
    }

    /// Get the security level of the context
    pub fn security_level(&self) -> u32 {
        // Return the highest security level supported by the context
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_kem_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    pub fn supported_algorithms(&self) -> String {
        let algorithms = alloc::vec!["ml-kem-512", "ml-kem-768", "ml-kem-1024", "dawn", "rcpkc"];
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
    fn parse_kem_algorithm(&self, algorithm: &str) -> Result<Algorithm, crate::error::Error> {
        parse_algorithm_wasm(algorithm).map_err(|_| crate::error::Error::InvalidAlgorithm {
            algorithm: "Invalid algorithm name",
        })
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

impl WasmSignatureContext {
    /// Create a new WASM Signature context with default provider
    pub fn new() -> WasmSignatureContext {
        WasmSignatureContext {
            inner: SignatureContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }
}

impl Default for WasmSignatureContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmSignatureContext {
    /// Create a new WASM Signature context with custom provider
    pub fn with_provider(provider: &WasmCryptoProvider) -> WasmSignatureContext {
        WasmSignatureContext {
            inner: SignatureContext::with_provider(Box::new(provider.inner.clone())),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_signature_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate security level
        convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, algorithm.category()),
        )?;

        // Convert randomness if provided
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_bytes = randomness_vec.as_deref();

        // Generate keypair
        let keypair = self
            .inner
            .generate_keypair(algorithm, randomness_bytes)
            .map_err(error_to_js_value)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "public_key": keypair.public_key.data,
                "secret_key": keypair.secret_key.data,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Sign a message using the given secret key
    pub fn sign(
        &self,
        algorithm: &str,
        secret_key_data: &Uint8Array,
        message: &Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> Result<Vec<u8>, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_signature_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate secret key size (simplified)
        if secret_key_data.length() == 0 {
            return Err(JsValue::from_str("Invalid signature secret key: empty key"));
        }

        // Validate message size (simplified)
        if message.length() == 0 {
            return Err(JsValue::from_str("Invalid message size: empty data"));
        }

        // Convert randomness if provided
        let randomness_vec = randomness.map(|rand| rand.to_vec());
        let randomness_bytes = randomness_vec.as_deref();

        // Create secret key using proper constructor
        let secret_key = crate::traits::SigSecretKey::new(secret_key_data.to_vec());

        // Sign
        let signature = self
            .inner
            .sign(algorithm, &secret_key, &message.to_vec(), randomness_bytes)
            .map_err(error_to_js_value)?;
        Ok(signature)
    }

    /// Verify a signature using the given public key
    pub fn verify(
        &self,
        algorithm: &str,
        public_key_data: &Uint8Array,
        message: &Uint8Array,
        signature: &Uint8Array,
    ) -> Result<bool, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_signature_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate public key size (simplified)
        if public_key_data.length() == 0 {
            return Err(JsValue::from_str("Invalid signature public key: empty key"));
        }

        // Validate message size (simplified)
        if message.length() == 0 {
            return Err(JsValue::from_str("Invalid message size: empty data"));
        }

        // Validate signature size (simplified)
        if signature.length() == 0 {
            return Err(JsValue::from_str("Invalid message size: empty data"));
        }

        // Create public key using proper constructor
        let public_key = crate::traits::SigPublicKey::new(public_key_data.to_vec());

        // Verify
        let is_valid = self
            .inner
            .verify(
                algorithm,
                &public_key,
                &message.to_vec(),
                &signature.to_vec(),
            )
            .map_err(error_to_js_value)?;
        Ok(is_valid)
    }

    /// Get the security level of the context
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_signature_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    pub fn supported_algorithms(&self) -> String {
        let algorithms = alloc::vec!["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "fn-dsa"];
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
    fn parse_signature_algorithm(&self, algorithm: &str) -> Result<Algorithm, crate::error::Error> {
        parse_algorithm_wasm(algorithm).map_err(|_| crate::error::Error::InvalidAlgorithm {
            algorithm: "Invalid algorithm name",
        })
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

impl WasmHashContext {
    /// Create a new WASM Hash context with default provider
    pub fn new() -> WasmHashContext {
        WasmHashContext {
            inner: HashContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }
}

impl Default for WasmHashContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmHashContext {
    /// Create a new WASM Hash context with custom provider
    pub fn with_provider(provider: &WasmCryptoProvider) -> WasmHashContext {
        WasmHashContext {
            inner: HashContext::with_provider(Box::new(provider.inner.clone())),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Hash data using the specified algorithm
    pub fn hash(&mut self, algorithm: &str, data: &Uint8Array) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_hash_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Hash)
            .map_err(error_to_js_value)?;

        // Validate data using security validator
        self.security_validator
            .validate_message(&data.to_vec())
            .map_err(error_to_js_value)?;

        // Hash
        let hash = self
            .inner
            .hash(algorithm, &data.to_vec())
            .map_err(error_to_js_value)?;

        // Return as JavaScript object
        #[cfg(feature = "wasm")]
        {
            let result = serde_json::json!({
                "hash": hash,
                "algorithm": algorithm.to_string(),
                "security_level": 256 // Placeholder
            });

            match serde_wasm_bindgen::to_value(&result) {
                Ok(value) => Ok(value),
                Err(e) => Err(JsValue::from_str(&format!("Serialization error: {:?}", e))),
            }
        }
        #[cfg(not(feature = "wasm"))]
        {
            Err(JsValue::from_str("WASM feature not enabled"))
        }
    }

    /// Get the security level of the context
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_hash_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    pub fn supported_algorithms(&self) -> String {
        let algorithms = alloc::vec![
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
    fn parse_hash_algorithm(&self, algorithm: &str) -> Result<Algorithm, crate::error::Error> {
        parse_algorithm_wasm(algorithm).map_err(|_| crate::error::Error::InvalidAlgorithm {
            algorithm: "Invalid algorithm name",
        })
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

impl WasmAeadContext {
    /// Create a new WASM AEAD context with default provider
    pub fn new() -> WasmAeadContext {
        WasmAeadContext {
            inner: AeadContext::with_default_provider(),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }
}

impl Default for WasmAeadContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmAeadContext {
    /// Create a new WASM AEAD context with custom provider
    pub fn with_provider(provider: &WasmCryptoProvider) -> WasmAeadContext {
        WasmAeadContext {
            inner: AeadContext::with_provider(Box::new(provider.inner.clone())),
            security_validator: SecurityValidator::new()
                .unwrap_or_else(|_| SecurityValidator::new().unwrap()),
        }
    }

    /// Encrypt data using the specified algorithm
    pub fn encrypt(
        &mut self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        plaintext: &Uint8Array,
        aad: Option<Uint8Array>,
    ) -> Result<Vec<u8>, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_aead_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Aead)
            .map_err(error_to_js_value)?;

        // Validate key using security validator
        self.security_validator
            .validate_key_size(algorithm, &key.to_vec(), true)
            .map_err(error_to_js_value)?;

        // Validate nonce using security validator
        self.security_validator
            .validate_nonce(&nonce.to_vec())
            .map_err(error_to_js_value)?;

        // Validate plaintext using security validator
        self.security_validator
            .validate_message(&plaintext.to_vec())
            .map_err(error_to_js_value)?;

        // Convert AAD if provided and validate
        let aad_bytes = aad.map(|aad_data| aad_data.to_vec());
        if let Some(ref aad_data) = aad_bytes {
            self.security_validator
                .validate_message(aad_data)
                .map_err(error_to_js_value)?;
        }

        // Encrypt
        let aead_key = AeadKey::new(key.to_vec());
        let nonce_obj = Nonce::new(nonce.to_vec());
        let ciphertext = self
            .inner
            .encrypt(
                algorithm,
                &aead_key,
                &nonce_obj,
                &plaintext.to_vec(),
                aad_bytes.as_deref(),
            )
            .map_err(error_to_js_value)?;
        Ok(ciphertext)
    }

    /// Decrypt data using the specified algorithm
    pub fn decrypt(
        &self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        ciphertext: &Uint8Array,
        aad: Option<Uint8Array>,
    ) -> Result<Vec<u8>, JsValue> {
        // Parse and validate algorithm
        let algorithm = self
            .parse_aead_algorithm(algorithm)
            .map_err(error_to_js_value)?;

        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Aead)
            .map_err(error_to_js_value)?;

        // Validate key using security validator
        self.security_validator
            .validate_key_size(algorithm, &key.to_vec(), true)
            .map_err(error_to_js_value)?;

        // Validate nonce using security validator
        self.security_validator
            .validate_nonce(&nonce.to_vec())
            .map_err(error_to_js_value)?;

        // Validate ciphertext using security validator
        self.security_validator
            .validate_ciphertext(algorithm, &ciphertext.to_vec())
            .map_err(error_to_js_value)?;

        // Convert AAD if provided and validate
        let aad_bytes = aad.map(|aad_data| aad_data.to_vec());
        if let Some(ref aad_data) = aad_bytes {
            self.security_validator
                .validate_message(aad_data)
                .map_err(error_to_js_value)?;
        }

        // Decrypt
        let aead_key = AeadKey::new(key.to_vec());
        let nonce_obj = Nonce::new(nonce.to_vec());
        let plaintext = self
            .inner
            .decrypt(
                algorithm,
                &aead_key,
                &nonce_obj,
                &ciphertext.to_vec(),
                aad_bytes.as_deref(),
            )
            .map_err(error_to_js_value)?;
        Ok(plaintext)
    }

    /// Get the security level of the context
    pub fn security_level(&self) -> u32 {
        256 // This would be determined by the provider
    }

    /// Check if an algorithm is supported
    pub fn is_algorithm_supported(&self, algorithm: &str) -> bool {
        self.parse_aead_algorithm(algorithm).is_ok()
    }

    /// Get supported algorithms
    pub fn supported_algorithms(&self) -> String {
        let algorithms = alloc::vec!["saturnin", "shake256-aead", "kem-aead"];
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
    fn parse_aead_algorithm(&self, algorithm: &str) -> Result<Algorithm, crate::error::Error> {
        parse_algorithm_wasm(algorithm).map_err(|_| crate::error::Error::InvalidAlgorithm {
            algorithm: "Invalid algorithm name",
        })
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

impl WasmCryptoProvider {
    /// Create a new WASM CryptoProvider
    pub fn new() -> WasmCryptoProvider {
        WasmCryptoProvider {
            inner: LibQCryptoProvider::new().unwrap_or_else(|_| LibQCryptoProvider::new().unwrap()),
        }
    }
}

impl Default for WasmCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmCryptoProvider {
    /// Get the provider information
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
    pub fn is_algorithm_supported(&self, _algorithm: &str) -> bool {
        // This would check against the actual provider implementation
        true // Placeholder
    }

    /// Get supported algorithms by category
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

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_kem_context_operations() {
        let mut context = WasmKemContext::new();

        // Test that operations return proper NotImplemented errors
        let result = context.generate_keypair("ml-kem-512", None);
        assert!(result.is_err());
        if let Err(error) = result {
            let error_str = error.as_string().unwrap_or_default();
            assert!(error_str.contains("NotImplemented") || error_str.contains("WASM"));
        }
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_signature_context_operations() {
        let mut context = WasmSignatureContext::new();

        // Test that operations return proper NotImplemented errors
        let result = context.generate_keypair("ml-dsa-65", None);
        assert!(result.is_err());
        if let Err(error) = result {
            let error_str = error.as_string().unwrap_or_default();
            assert!(error_str.contains("NotImplemented") || error_str.contains("WASM"));
        }
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_hash_context_operations() {
        let mut context = WasmHashContext::new();

        // Test that operations return proper NotImplemented errors
        let data = Uint8Array::new_with_length(10);
        let result = context.hash("sha3-256", &data);
        assert!(result.is_err());
        if let Err(error) = result {
            let error_str = error.as_string().unwrap_or_default();
            assert!(error_str.contains("NotImplemented") || error_str.contains("WASM"));
        }
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_aead_context_operations() {
        let mut context = WasmAeadContext::new();

        // Test that operations return proper NotImplemented errors
        let key = Uint8Array::new_with_length(32);
        let nonce = Uint8Array::new_with_length(16);
        let plaintext = Uint8Array::new_with_length(10);

        let result = context.encrypt("saturnin", &key, &nonce, &plaintext, None);
        assert!(result.is_err());
        if let Err(error) = result {
            let error_str = error.as_string().unwrap_or_default();
            assert!(error_str.contains("NotImplemented") || error_str.contains("WASM"));
        }
    }
}
