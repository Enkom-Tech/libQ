//! KEM (Key Encapsulation Mechanism) provider implementation
//!
//! This module provides the LibQKemProvider that implements KEM operations
//! with proper security validation and algorithm routing.

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use crate::api::{
    Algorithm,
    KemOperations,
};
use crate::error::Result;
use crate::security::SecurityValidator;
use crate::traits::{
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};

/// lib-Q KEM provider implementation
///
/// This provider implements KEM operations for lib-Q, including key generation,
/// encapsulation, and decapsulation with proper security validation.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQKemProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl LibQKemProvider {
    /// Create a new KEM provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQKemProvider with security validation initialized.
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
impl KemOperations for LibQKemProvider {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-KEM implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Dawn => Err(crate::error::Error::NotImplemented {
                feature: "DAWN implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }

    fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-KEM implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Dawn => Err(crate::error::Error::NotImplemented {
                feature: "DAWN implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-KEM implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Dawn => Err(crate::error::Error::NotImplemented {
                feature: "DAWN implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }

    fn derive_public_key(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
    ) -> Result<KemPublicKey> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-KEM implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Dawn => Err(crate::error::Error::NotImplemented {
                feature: "DAWN implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_kem_provider_creation() {
        let provider = LibQKemProvider::new();
        assert!(
            provider.is_ok(),
            "LibQKemProvider should be created successfully"
        );
    }

    #[test]
    fn test_kem_provider_unsupported_algorithm() {
        let provider = LibQKemProvider::new().unwrap();
        let result = provider.generate_keypair(Algorithm::Sha3_256, None);
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
    fn test_kem_provider_feature_flag_handling() {
        let provider = LibQKemProvider::new().unwrap();

        // Test ML-KEM without feature flag
        let result = provider.generate_keypair(Algorithm::MlKem512, None);
        assert!(
            result.is_err(),
            "Should return error when feature flag is not enabled"
        );

        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(
                feature.contains("ML-KEM implementations are provided by the main lib-q crate"),
                "Error should mention that implementations are provided by main lib-q crate"
            );
        } else {
            panic!("Expected NotImplemented error");
        }
    }
}
