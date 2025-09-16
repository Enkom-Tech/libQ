//! Secure WASM Contexts
//!
//! This module provides secure, production-ready WASM contexts that implement
//! proper error handling, security validation, and consistent API design.
//!
//! These contexts provide a unified interface for post-quantum cryptographic
//! operations in WebAssembly environments with comprehensive security validation
//! and protection against common attack vectors.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::api::{
    // Algorithm,
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
    // SigPublicKey,
};
use crate::wasm::error::{
    convert_result,
    // error_to_js_value,
    parse_algorithm_wasm,
    secure_serialize,
};

/// Secure WASM KEM Context
///
/// This context provides secure KEM operations with:
/// - Consistent error handling using Result<T, JsValue>
/// - Security validation for all inputs
/// - Protection against timing attacks
/// - Memory safety with automatic cleanup
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SecureWasmKemContext {
    inner: KemContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SecureWasmKemContext {
    /// Create a new secure WASM KEM context
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Result<SecureWasmKemContext, JsValue> {
        let provider = match LibQCryptoProvider::new() {
            Ok(provider) => Box::new(provider),
            Err(error) => return Err(error.into()),
        };
        let inner = KemContext::with_provider(provider);
        let security_validator = match SecurityValidator::new() {
            Ok(validator) => validator,
            Err(error) => return Err(error.into()),
        };

        Ok(SecureWasmKemContext {
            inner,
            security_validator,
        })
    }

    /// Generate a KEM keypair
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Kem),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert randomness if provided
        let randomness_bytes = randomness.map(|rand| rand.to_vec());

        // Generate keypair
        let keypair = convert_result(
            self.inner
                .generate_keypair(algorithm, randomness_bytes.as_deref()),
        )?;

        // Serialize and return
        match secure_serialize(&keypair) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Encapsulate a shared secret
    pub fn encapsulate(
        &self,
        algorithm: &str,
        public_key: &Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Kem),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let public_key_bytes = public_key.to_vec();
        let randomness_bytes = randomness.map(|rand| rand.to_vec());

        // Validate key size
        match convert_result(self.security_validator.validate_key_size(
            algorithm,
            &public_key_bytes,
            false,
        )) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create proper key type
        let public_key = crate::traits::KemPublicKey::new(public_key_bytes.to_vec());

        // Encapsulate
        let result = convert_result(self.inner.encapsulate(
            algorithm,
            &public_key,
            randomness_bytes.as_deref(),
        ))?;

        // Serialize and return
        match secure_serialize(&result) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Decapsulate a shared secret
    pub fn decapsulate(
        &self,
        algorithm: &str,
        private_key: &Uint8Array,
        ciphertext: &Uint8Array,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Kem),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let private_key_bytes = private_key.to_vec();
        let ciphertext_bytes = ciphertext.to_vec();

        // Validate key size
        match convert_result(self.security_validator.validate_key_size(
            algorithm,
            &private_key_bytes,
            true,
        )) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create proper key type
        let secret_key = crate::traits::KemSecretKey::new(private_key_bytes.to_vec());

        // Decapsulate
        let result = convert_result(self.inner.decapsulate(
            algorithm,
            &secret_key,
            &ciphertext_bytes,
        ))?;

        // Serialize and return
        match secure_serialize(&result) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Get supported algorithms
    pub fn get_supported_algorithms(&self) -> Result<JsValue, JsValue> {
        let algorithms = alloc::vec!["ml-kem-512", "ml-kem-768", "ml-kem-1024", "dawn", "rcpkc"];
        match secure_serialize(&algorithms) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }
}

/// Secure WASM Signature Context
///
/// This context provides secure signature operations with:
/// - Consistent error handling using Result<T, JsValue>
/// - Security validation for all inputs
/// - Protection against timing attacks
/// - Memory safety with automatic cleanup
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SecureWasmSignatureContext {
    inner: SignatureContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SecureWasmSignatureContext {
    /// Create a new secure WASM signature context
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Result<SecureWasmSignatureContext, JsValue> {
        let provider = match LibQCryptoProvider::new() {
            Ok(provider) => Box::new(provider),
            Err(error) => return Err(error.into()),
        };
        let inner = SignatureContext::with_provider(provider);
        let security_validator = match SecurityValidator::new() {
            Ok(validator) => validator,
            Err(error) => return Err(error.into()),
        };

        Ok(SecureWasmSignatureContext {
            inner,
            security_validator,
        })
    }

    /// Generate a signature keypair
    pub fn generate_keypair(
        &mut self,
        algorithm: &str,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Signature),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert randomness if provided
        let randomness_bytes = randomness.map(|rand| rand.to_vec());

        // Generate keypair
        let keypair = convert_result(
            self.inner
                .generate_keypair(algorithm, randomness_bytes.as_deref()),
        )?;

        // Serialize and return
        match secure_serialize(&keypair) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Sign a message
    pub fn sign(
        &self,
        algorithm: &str,
        private_key: &Uint8Array,
        message: &Uint8Array,
        randomness: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Signature),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let private_key_bytes = private_key.to_vec();
        let message_bytes = message.to_vec();
        let randomness_bytes = randomness.map(|rand| rand.to_vec());

        // Validate key size
        match convert_result(self.security_validator.validate_key_size(
            algorithm,
            &private_key_bytes,
            true,
        )) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate message size
        match convert_result(self.security_validator.validate_message(&message_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create proper key type
        let secret_key = crate::traits::SigSecretKey::new(private_key_bytes.to_vec());

        // Sign
        let signature = convert_result(self.inner.sign(
            algorithm,
            &secret_key,
            &message_bytes,
            randomness_bytes.as_deref(),
        ))?;

        // Serialize and return
        match secure_serialize(&signature) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        algorithm: &str,
        public_key: &Uint8Array,
        message: &Uint8Array,
        signature: &Uint8Array,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Signature),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let public_key_bytes = public_key.to_vec();
        let message_bytes = message.to_vec();
        let signature_bytes = signature.to_vec();

        // Validate key size
        match convert_result(self.security_validator.validate_key_size(
            algorithm,
            &public_key_bytes,
            false,
        )) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate message size
        match convert_result(self.security_validator.validate_message(&message_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create proper key type
        let public_key = crate::traits::SigPublicKey::new(public_key_bytes.to_vec());

        // Verify
        let is_valid = convert_result(self.inner.verify(
            algorithm,
            &public_key,
            &message_bytes,
            &signature_bytes,
        ))?;

        // Serialize and return
        match secure_serialize(&is_valid) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Get supported algorithms
    pub fn get_supported_algorithms(&self) -> Result<JsValue, JsValue> {
        let algorithms = alloc::vec!["ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "fn-dsa"];
        match secure_serialize(&algorithms) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }
}

/// Secure WASM Hash Context
///
/// This context provides secure hash operations with:
/// - Consistent error handling using Result<T, JsValue>
/// - Security validation for all inputs
/// - Protection against timing attacks
/// - Memory safety with automatic cleanup
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SecureWasmHashContext {
    inner: HashContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SecureWasmHashContext {
    /// Create a new secure WASM hash context
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Result<SecureWasmHashContext, JsValue> {
        let provider = match LibQCryptoProvider::new() {
            Ok(provider) => Box::new(provider),
            Err(error) => return Err(error.into()),
        };
        let inner = HashContext::with_provider(provider);
        let security_validator = match SecurityValidator::new() {
            Ok(validator) => validator,
            Err(error) => return Err(error.into()),
        };

        Ok(SecureWasmHashContext {
            inner,
            security_validator,
        })
    }

    /// Hash data
    pub fn hash(&mut self, algorithm: &str, data: &Uint8Array) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Hash),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let data_bytes = data.to_vec();

        // Validate message size
        match convert_result(self.security_validator.validate_message(&data_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Hash
        let hash = convert_result(self.inner.hash(algorithm, &data_bytes))?;

        // Serialize and return
        match secure_serialize(&hash) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Get supported algorithms
    pub fn get_supported_algorithms(&self) -> Result<JsValue, JsValue> {
        let algorithms = alloc::vec![
            "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256",
        ];
        match secure_serialize(&algorithms) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }
}

/// Secure WASM AEAD Context
///
/// This context provides secure AEAD operations with:
/// - Consistent error handling using Result<T, JsValue>
/// - Security validation for all inputs
/// - Protection against timing attacks
/// - Memory safety with automatic cleanup
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SecureWasmAeadContext {
    inner: AeadContext,
    security_validator: SecurityValidator,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SecureWasmAeadContext {
    /// Create a new secure WASM AEAD context
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Result<SecureWasmAeadContext, JsValue> {
        let provider = match LibQCryptoProvider::new() {
            Ok(provider) => Box::new(provider),
            Err(error) => return Err(error.into()),
        };
        let inner = AeadContext::with_provider(provider);
        let security_validator = match SecurityValidator::new() {
            Ok(validator) => validator,
            Err(error) => return Err(error.into()),
        };

        Ok(SecureWasmAeadContext {
            inner,
            security_validator,
        })
    }

    /// Encrypt data
    pub fn encrypt(
        &mut self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        plaintext: &Uint8Array,
        associated_data: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Aead),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let key_bytes = key.to_vec();
        let nonce_bytes = nonce.to_vec();
        let plaintext_bytes = plaintext.to_vec();
        let associated_data_bytes = associated_data.map(|ad| ad.to_vec());

        // Validate key size
        match convert_result(
            self.security_validator
                .validate_key_size(algorithm, &key_bytes, true),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate nonce
        match convert_result(self.security_validator.validate_nonce(&nonce_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate message size
        match convert_result(self.security_validator.validate_message(&plaintext_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create key and nonce objects
        let aead_key = AeadKey::new(key_bytes.to_vec());
        let aead_nonce = Nonce::new(nonce_bytes.to_vec());

        // Encrypt
        let ciphertext = convert_result(self.inner.encrypt(
            algorithm,
            &aead_key,
            &aead_nonce,
            &plaintext_bytes,
            associated_data_bytes.as_deref(),
        ))?;

        // Serialize and return
        match secure_serialize(&ciphertext) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Decrypt data
    pub fn decrypt(
        &self,
        algorithm: &str,
        key: &Uint8Array,
        nonce: &Uint8Array,
        ciphertext: &Uint8Array,
        associated_data: Option<Uint8Array>,
    ) -> Result<JsValue, JsValue> {
        // Parse and validate algorithm
        let algorithm = parse_algorithm_wasm(algorithm)?;

        // Validate algorithm category
        match convert_result(
            self.security_validator
                .validate_algorithm_category(algorithm, AlgorithmCategory::Aead),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Convert inputs
        let key_bytes = key.to_vec();
        let nonce_bytes = nonce.to_vec();
        let ciphertext_bytes = ciphertext.to_vec();
        let associated_data_bytes = associated_data.map(|ad| ad.to_vec());

        // Validate key size
        match convert_result(
            self.security_validator
                .validate_key_size(algorithm, &key_bytes, true),
        ) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate nonce
        match convert_result(self.security_validator.validate_nonce(&nonce_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Validate message size
        match convert_result(self.security_validator.validate_message(&ciphertext_bytes)) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        // Create key and nonce objects
        let aead_key = AeadKey::new(key_bytes.to_vec());
        let aead_nonce = Nonce::new(nonce_bytes.to_vec());

        // Decrypt
        let plaintext = convert_result(self.inner.decrypt(
            algorithm,
            &aead_key,
            &aead_nonce,
            &ciphertext_bytes,
            associated_data_bytes.as_deref(),
        ))?;

        // Serialize and return
        match secure_serialize(&plaintext) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Get supported algorithms
    pub fn get_supported_algorithms(&self) -> Result<JsValue, JsValue> {
        let algorithms = alloc::vec!["saturnin", "shake256-aead", "kem-aead"];
        match secure_serialize(&algorithms) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }
}
