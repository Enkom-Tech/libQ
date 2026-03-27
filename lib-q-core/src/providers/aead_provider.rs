//! AEAD stub provider (core only)
//!
//! [`LibQAeadStubProvider`] validates inputs then returns [`NotImplemented`](crate::error::Error::NotImplemented).
//! Registry-backed AEAD lives in the `lib-q-aead` crate as `LibQAeadProvider`.

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use crate::api::{
    AeadOperations,
    Algorithm,
};
use crate::error::Result;
use crate::security::SecurityValidator;
use crate::traits::{
    AeadKey,
    Nonce,
};

/// Stub AEAD provider bundled with `lib-q-core` (no algorithm implementations).
///
/// Use `lib_q_aead::LibQAeadProvider` or the `lib-q` crate’s `libq::aead::context()` for real AEAD.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQAeadStubProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl LibQAeadStubProvider {
    /// Create a new stub AEAD provider.
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(feature = "alloc")]
impl AeadOperations for LibQAeadStubProvider {
    fn encrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Aead)?;

        // Validate key
        self.security_validator
            .validate_key_material(key.as_bytes())?;

        // Validate nonce
        self.security_validator.validate_nonce(nonce.as_bytes())?;

        // Validate plaintext
        self.security_validator.validate_message(plaintext)?;

        // Validate associated data if present
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        Err(crate::error::Error::NotImplemented {
            feature: "AEAD — use `lib_q_aead::LibQAeadProvider`, `libq::aead::context()`, or `AeadContext::with_aead_operations`"
                .to_string(),
        })
    }

    fn decrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Aead)?;

        // Validate key
        self.security_validator
            .validate_key_material(key.as_bytes())?;

        // Validate nonce
        self.security_validator.validate_nonce(nonce.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Validate associated data if present
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        Err(crate::error::Error::NotImplemented {
            feature: "AEAD — use `lib_q_aead::LibQAeadProvider`, `libq::aead::context()`, or `AeadContext::with_aead_operations`"
                .to_string(),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_aead_stub_provider_creation() {
        let provider = LibQAeadStubProvider::new();
        assert!(
            provider.is_ok(),
            "LibQAeadStubProvider should be created successfully"
        );
    }

    #[test]
    fn test_aead_stub_unsupported_algorithm() {
        let provider = LibQAeadStubProvider::new().unwrap();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let result = provider.encrypt(Algorithm::MlKem512, &key, &nonce, b"test", None);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );

        if let Err(crate::error::Error::InvalidAlgorithm { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }

    #[test]
    fn test_aead_stub_unregistered_aead_algorithm() {
        let provider = LibQAeadStubProvider::new().unwrap();
        let key = AeadKey::new(vec![
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7,
            0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5,
            0xD6, 0xE7, 0xF8, 0x09,
        ]);
        let nonce = Nonce::new(vec![
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7,
            0xF8, 0x09,
        ]);

        // Test Saturnin without feature flag
        let result = provider.encrypt(Algorithm::Saturnin, &key, &nonce, b"test", None);
        assert!(
            result.is_err(),
            "Should return error when feature flag is not enabled"
        );

        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(
                feature.contains("LibQAeadProvider") || feature.contains("libq::aead::context"),
                "Error should direct callers to lib-q-aead / libq::aead::context(): {feature}"
            );
        } else {
            panic!("Expected NotImplemented error, got: {:?}", result);
        }
    }
}
