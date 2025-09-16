//! AEAD provider implementation
//!
//! This module provides the LibQAeadProvider that implements AEAD operations
//! with proper security validation and algorithm routing.

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

/// lib-Q AEAD provider implementation
///
/// This provider implements AEAD operations for lib-Q, including encryption
/// and decryption with proper security validation.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQAeadProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl LibQAeadProvider {
    /// Create a new AEAD provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQAeadProvider with security validation initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if the security validator fails to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(feature = "alloc")]
impl AeadOperations for LibQAeadProvider {
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

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::Saturnin => Err(crate::error::Error::NotImplemented {
                feature: "Saturnin implementation is provided by the main lib-q crate".to_string(),
            }),
            Algorithm::Shake256Aead => Err(crate::error::Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation is provided by the main lib-q crate"
                    .to_string(),
            }),
            Algorithm::KemAead => Err(crate::error::Error::NotImplemented {
                feature: "KEM AEAD implementation is provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for AEAD operations",
            }),
        }
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

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::Saturnin => Err(crate::error::Error::NotImplemented {
                feature: "Saturnin implementation is provided by the main lib-q crate".to_string(),
            }),
            Algorithm::Shake256Aead => Err(crate::error::Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation is provided by the main lib-q crate"
                    .to_string(),
            }),
            Algorithm::KemAead => Err(crate::error::Error::NotImplemented {
                feature: "KEM AEAD implementation is provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for AEAD operations",
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_aead_provider_creation() {
        let provider = LibQAeadProvider::new();
        assert!(
            provider.is_ok(),
            "LibQAeadProvider should be created successfully"
        );
    }

    #[test]
    fn test_aead_provider_unsupported_algorithm() {
        let provider = LibQAeadProvider::new().unwrap();
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
    fn test_aead_provider_feature_flag_handling() {
        let provider = LibQAeadProvider::new().unwrap();
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
                feature.contains("Saturnin implementation is provided by the main lib-q crate"),
                "Error should mention that implementations are provided by main lib-q crate"
            );
        } else {
            panic!("Expected NotImplemented error, got: {:?}", result);
        }
    }
}
