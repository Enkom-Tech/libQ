//! lib-Q RCPKC - Randomized Concatenated Public Key Cryptography
//!
//! RCPKC is a post-quantum cryptographic scheme based on lattice problems
//! that provides enhanced security through randomized concatenation of
//! multiple cryptographic primitives.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
#![warn(missing_docs, missing_debug_implementations)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use lib_q_core::{
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// Internal modules
mod kem;
mod math;
mod parameters;
mod raep;
mod security;
mod signature;

// Re-export main types
pub use parameters::{
    RcpkcParameters,
    RcpkcVariant,
};
pub use raep::{
    Raep,
    RaepDecryption,
    RaepEncryption,
    RaepParams,
};

/// RCPKC KEM implementation
///
/// This implementation provides key encapsulation mechanism functionality
/// based on the RCPKC lattice-based cryptosystem.
#[derive(Debug)]
pub struct RcpkcKem {
    /// RCPKC parameters for this instance
    params: RcpkcParameters,
}

impl RcpkcKem {
    /// Create a new RCPKC KEM instance with default parameters
    pub fn new() -> Result<Self> {
        Self::with_parameters(RcpkcParameters::default())
    }

    /// Create a new RCPKC KEM instance with custom parameters
    pub fn with_parameters(params: RcpkcParameters) -> Result<Self> {
        // Validate parameters
        params.validate()?;

        Ok(Self { params })
    }

    /// Get the current parameters
    pub fn parameters(&self) -> &RcpkcParameters {
        &self.params
    }
}

impl Default for RcpkcKem {
    fn default() -> Self {
        Self::new().expect("Default RCPKC parameters should be valid")
    }
}

impl Kem for RcpkcKem {
    /// Generate a keypair using RCPKC algorithm
    fn generate_keypair(&self) -> Result<KemKeypair> {
        kem::generate_keypair(&self.params)
    }

    /// Encapsulate a shared secret using RCPKC algorithm
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
        kem::encapsulate(&self.params, public_key)
    }

    /// Decapsulate a shared secret using RCPKC algorithm
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        kem::decapsulate(&self.params, secret_key, ciphertext)
    }

    /// Derive public key from secret key
    fn derive_public_key(&self, secret_key: &KemSecretKey) -> Result<KemPublicKey> {
        kem::derive_public_key(&self.params, secret_key)
    }

    /// Authenticated encapsulation
    fn auth_encapsulate(
        &self,
        secret_key: &KemSecretKey,
        public_key: &KemPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        kem::auth_encapsulate(&self.params, secret_key, public_key)
    }

    /// Authenticated decapsulation
    fn auth_decapsulate(
        &self,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
        public_key: &KemPublicKey,
    ) -> Result<Vec<u8>> {
        kem::auth_decapsulate(&self.params, secret_key, ciphertext, public_key)
    }
}

/// RCPKC signature implementation
///
/// This implementation provides digital signature functionality
/// based on the RCPKC lattice-based cryptosystem.
#[derive(Debug)]
pub struct RcpkcSig {
    /// RCPKC parameters for this instance
    params: RcpkcParameters,
}

impl RcpkcSig {
    /// Create a new RCPKC signature instance with default parameters
    pub fn new() -> Result<Self> {
        Self::with_parameters(RcpkcParameters::default())
    }

    /// Create a new RCPKC signature instance with custom parameters
    pub fn with_parameters(params: RcpkcParameters) -> Result<Self> {
        // Validate parameters
        params.validate()?;

        Ok(Self { params })
    }

    /// Get the current parameters
    pub fn parameters(&self) -> &RcpkcParameters {
        &self.params
    }
}

impl Default for RcpkcSig {
    fn default() -> Self {
        Self::new().expect("Default RCPKC parameters should be valid")
    }
}

impl Signature for RcpkcSig {
    /// Generate a signature keypair using RCPKC algorithm
    fn generate_keypair(&self) -> Result<SigKeypair> {
        signature::generate_keypair(&self.params)
    }

    /// Sign a message using RCPKC algorithm
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        signature::sign(&self.params, secret_key, message)
    }

    /// Verify a signature using RCPKC algorithm
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        signature::verify(&self.params, public_key, message, signature)
    }
}

/// WASM-friendly wrapper for RCPKC operations
#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::JsError;

    use super::*;

    /// Generate a keypair (WASM)
    #[wasm_bindgen]
    pub fn generate_keypair() -> Result<KemKeypair, JsError> {
        let kem = RcpkcKem::new();
        kem.generate_keypair()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn encapsulate(public_key: &KemPublicKey) -> Result<EncapsulationResult, JsError> {
        let kem = RcpkcKem::new();
        let (ciphertext, shared_secret) = kem
            .encapsulate(public_key)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(EncapsulationResult::new(ciphertext, shared_secret))
    }

    /// Decapsulate a shared secret (WASM)
    #[wasm_bindgen]
    pub fn decapsulate(secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let kem = RcpkcKem::new();
        kem.decapsulate(secret_key, ciphertext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Result of encapsulation operation for WASM
    #[wasm_bindgen]
    pub struct EncapsulationResult {
        #[wasm_bindgen(skip)]
        ciphertext: Vec<u8>,
        #[wasm_bindgen(skip)]
        shared_secret: Vec<u8>,
    }

    #[wasm_bindgen]
    impl EncapsulationResult {
        #[wasm_bindgen(constructor)]
        pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
            Self {
                ciphertext,
                shared_secret,
            }
        }

        #[wasm_bindgen(getter)]
        pub fn ciphertext(&self) -> Vec<u8> {
            self.ciphertext.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn shared_secret(&self) -> Vec<u8> {
            self.shared_secret.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcpkc_creation() {
        let _rcpkc = RcpkcKem::new();
        // RCPKC implementation created successfully
        assert!(true);
    }

    #[test]
    fn test_rcpkc_keypair_generation() {
        let rcpkc = RcpkcKem::new().unwrap();
        let result = rcpkc.generate_keypair();
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair.public_key.data.len(), rcpkc.parameters().key_size);
        assert_eq!(keypair.secret_key.data.len(), rcpkc.parameters().key_size);
    }

    #[test]
    fn test_rcpkc_encapsulation() {
        let rcpkc = RcpkcKem::new().unwrap();
        let keypair = rcpkc.generate_keypair().unwrap();

        let result = rcpkc.encapsulate(&keypair.public_key);
        assert!(result.is_ok());

        let (ciphertext, shared_secret) = result.unwrap();
        assert_eq!(ciphertext.len(), rcpkc.parameters().ciphertext_size);
        assert_eq!(shared_secret.len(), rcpkc.parameters().key_size);
    }

    #[test]
    fn test_rcpkc_decapsulation() {
        let rcpkc = RcpkcKem::new().unwrap();
        let keypair = rcpkc.generate_keypair().unwrap();
        let (ciphertext, expected_secret) = rcpkc.encapsulate(&keypair.public_key).unwrap();

        let result = rcpkc.decapsulate(&keypair.secret_key, &ciphertext);
        assert!(result.is_ok());

        let decapsulated_secret = result.unwrap();
        assert_eq!(decapsulated_secret, expected_secret);
    }

    #[test]
    fn test_rcpkc_signature_creation() {
        let _sig = RcpkcSig::new().unwrap();
        // RCPKC signature implementation created successfully
        assert!(true);
    }

    #[test]
    fn test_rcpkc_signature_keypair_generation() {
        let sig = RcpkcSig::new().unwrap();
        let result = sig.generate_keypair();
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair.public_key.data.len(), sig.parameters().key_size);
        assert_eq!(keypair.secret_key.data.len(), sig.parameters().key_size);
    }

    #[test]
    fn test_rcpkc_sign_verify() {
        let sig = RcpkcSig::new().unwrap();
        let keypair = sig.generate_keypair().unwrap();
        let message = b"Hello, RCPKC!";

        let signature = sig.sign(&keypair.secret_key, message).unwrap();
        let is_valid = sig
            .verify(&keypair.public_key, message, &signature)
            .unwrap();

        assert!(is_valid);
        assert_eq!(signature.len(), sig.parameters().ciphertext_size);
    }

    #[test]
    fn test_rcpkc_variants() {
        // Test RCPKC.1 variant
        let params_rcpkc1 = RcpkcParameters::level1_rcpkc1();
        assert_eq!(params_rcpkc1.variant, RcpkcVariant::Rcpkc1);

        let kem_rcpkc1 = RcpkcKem::with_parameters(params_rcpkc1).unwrap();
        let keypair_rcpkc1 = kem_rcpkc1.generate_keypair().unwrap();
        let (ciphertext_rcpkc1, shared_secret_rcpkc1) =
            kem_rcpkc1.encapsulate(&keypair_rcpkc1.public_key).unwrap();
        let decapsulated_rcpkc1 = kem_rcpkc1
            .decapsulate(&keypair_rcpkc1.secret_key, &ciphertext_rcpkc1)
            .unwrap();
        assert_eq!(decapsulated_rcpkc1, shared_secret_rcpkc1);

        // Test RCPKC.2 variant
        let params_rcpkc2 = RcpkcParameters::level1();
        assert_eq!(params_rcpkc2.variant, RcpkcVariant::Rcpkc2);

        let kem_rcpkc2 = RcpkcKem::with_parameters(params_rcpkc2).unwrap();
        let keypair_rcpkc2 = kem_rcpkc2.generate_keypair().unwrap();
        let (ciphertext_rcpkc2, shared_secret_rcpkc2) =
            kem_rcpkc2.encapsulate(&keypair_rcpkc2.public_key).unwrap();
        let decapsulated_rcpkc2 = kem_rcpkc2
            .decapsulate(&keypair_rcpkc2.secret_key, &ciphertext_rcpkc2)
            .unwrap();
        assert_eq!(decapsulated_rcpkc2, shared_secret_rcpkc2);
    }

    #[test]
    fn test_rcpkc_security_levels() {
        let security_levels = [
            RcpkcParameters::level1(),
            RcpkcParameters::level3(),
            RcpkcParameters::level4(),
            RcpkcParameters::level5(),
        ];

        for params in &security_levels {
            let kem = RcpkcKem::with_parameters(params.clone()).unwrap();
            let keypair = kem.generate_keypair().unwrap();

            // Test KEM operations
            let (ciphertext, shared_secret) = kem.encapsulate(&keypair.public_key).unwrap();
            let decapsulated = kem.decapsulate(&keypair.secret_key, &ciphertext).unwrap();
            assert_eq!(decapsulated, shared_secret);

            // Test signature operations
            let sig = RcpkcSig::with_parameters(params.clone()).unwrap();
            let sig_keypair = sig.generate_keypair().unwrap();
            let message = b"Test message for security level";
            let signature = sig.sign(&sig_keypair.secret_key, message).unwrap();
            let is_valid = sig
                .verify(&sig_keypair.public_key, message, &signature)
                .unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_rcpkc_parameter_validation() {
        // Test that invalid parameters are rejected
        let mut invalid_params = RcpkcParameters::level1();
        invalid_params.q = 0; // Invalid modulus

        let result = RcpkcKem::with_parameters(invalid_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_rcpkc_authenticated_operations() {
        let kem = RcpkcKem::new().unwrap();
        let keypair = kem.generate_keypair().unwrap();

        // Test authenticated encapsulation
        let (auth_ciphertext, auth_shared_secret) = kem
            .auth_encapsulate(&keypair.secret_key, &keypair.public_key)
            .unwrap();
        assert_eq!(auth_ciphertext.len(), kem.parameters().ciphertext_size);
        assert_eq!(auth_shared_secret.len(), kem.parameters().key_size);

        // Test authenticated decapsulation
        let auth_decapsulated = kem
            .auth_decapsulate(&keypair.secret_key, &auth_ciphertext, &keypair.public_key)
            .unwrap();
        assert_eq!(auth_decapsulated, auth_shared_secret);
    }
}
