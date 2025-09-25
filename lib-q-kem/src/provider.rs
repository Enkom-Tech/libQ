//! lib-Q KEM Provider Implementation
//!
//! This module provides the LibQKemProvider that implements the KemOperations
//! trait and routes KEM operations to the appropriate algorithm implementations
//! with proper security validation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

// Import Classical McEliece implementations
#[cfg(feature = "cb-kem")]
use lib_q_cb_kem::LibQCbKemProvider;
#[cfg(feature = "alloc")]
use lib_q_core::api::{
    Algorithm,
    CryptoProvider,
    KemOperations,
};
#[cfg(feature = "alloc")]
use lib_q_core::error::{
    Error,
    Result,
};
#[cfg(feature = "alloc")]
use lib_q_core::security::SecurityValidator;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};

// Import algorithm implementations
#[cfg(feature = "ml-kem")]
use crate::ml_kem::{
    MlKem512Impl,
    MlKem768Impl,
    MlKem1024Impl,
};

/// lib-Q KEM provider implementation
///
/// This provider implements KEM operations for lib-Q, including key generation,
/// encapsulation, and decapsulation with proper security validation and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQKemProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for LibQKemProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibQKemProvider")
            .field("security_validator", &"<SecurityValidator>")
            .finish()
    }
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

    /// Get the security validator
    pub fn security_validator(&self) -> &SecurityValidator {
        &self.security_validator
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
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.generate_keypair()
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.generate_keypair()
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.generate_keypair()
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.generate_keypair(algorithm, randomness)
            }

            // DAWN KEM algorithm
            #[cfg(feature = "dawn")]
            Algorithm::Dawn => {
                // TODO: Implement DAWN KEM when available
                Err(Error::NotImplemented {
                    feature: "DAWN KEM implementation not yet available".to_string(),
                })
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM implementations require 'ml-kem' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: "CB-KEM implementations require 'cb-kem' feature flag".to_string(),
            }),
            #[cfg(not(feature = "dawn"))]
            Algorithm::Dawn => Err(Error::NotImplemented {
                feature: "DAWN KEM implementation requires 'dawn' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
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
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.encapsulate(public_key)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.encapsulate(algorithm, public_key, randomness)
            }

            // DAWN KEM algorithm
            #[cfg(feature = "dawn")]
            Algorithm::Dawn => {
                // TODO: Implement DAWN KEM when available
                Err(Error::NotImplemented {
                    feature: "DAWN KEM implementation not yet available".to_string(),
                })
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM implementations require 'ml-kem' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: "CB-KEM implementations require 'cb-kem' feature flag".to_string(),
            }),
            #[cfg(not(feature = "dawn"))]
            Algorithm::Dawn => Err(Error::NotImplemented {
                feature: "DAWN KEM implementation requires 'dawn' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
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
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.decapsulate(secret_key, ciphertext)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.decapsulate(algorithm, secret_key, ciphertext)
            }

            // DAWN KEM algorithm
            #[cfg(feature = "dawn")]
            Algorithm::Dawn => {
                // TODO: Implement DAWN KEM when available
                Err(Error::NotImplemented {
                    feature: "DAWN KEM implementation not yet available".to_string(),
                })
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM implementations require 'ml-kem' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: "CB-KEM implementations require 'cb-kem' feature flag".to_string(),
            }),
            #[cfg(not(feature = "dawn"))]
            Algorithm::Dawn => Err(Error::NotImplemented {
                feature: "DAWN KEM implementation requires 'dawn' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
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
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Route to specific algorithm implementation
        match algorithm {
            // ML-KEM algorithms
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 => {
                let kem = MlKem512Impl::default();
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem768 => {
                let kem = MlKem768Impl::default();
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem1024 => {
                let kem = MlKem1024Impl::default();
                kem.derive_public_key(secret_key)
            }

            // CB-KEM algorithms
            #[cfg(feature = "cb-kem")]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => {
                let cb_kem_provider = LibQCbKemProvider::new()?;
                cb_kem_provider.derive_public_key(algorithm, secret_key)
            }

            // DAWN KEM algorithm
            #[cfg(feature = "dawn")]
            Algorithm::Dawn => {
                // TODO: Implement DAWN KEM when available
                Err(Error::NotImplemented {
                    feature: "DAWN KEM implementation not yet available".to_string(),
                })
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM implementations require 'ml-kem' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: "CB-KEM implementations require 'cb-kem' feature flag".to_string(),
            }),
            #[cfg(not(feature = "dawn"))]
            Algorithm::Dawn => Err(Error::NotImplemented {
                feature: "DAWN KEM implementation requires 'dawn' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for KEM operations",
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQKemProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(self)
    }

    fn signature(&self) -> Option<&dyn lib_q_core::api::SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn lib_q_core::api::HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn lib_q_core::api::AeadOperations> {
        None
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = LibQKemProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_security_validator() {
        let provider = LibQKemProvider::new().unwrap();
        let _validator = provider.security_validator();
        // Security validator should be accessible
    }

    #[test]
    fn test_provider_unsupported_algorithm() {
        let provider = LibQKemProvider::new().unwrap();
        let result = provider.generate_keypair(Algorithm::Sha3_256, None);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );

        if let Err(Error::InvalidAlgorithm { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }

    #[test]
    fn test_provider_feature_flag_handling() {
        let _provider = LibQKemProvider::new().unwrap();

        // Test ML-KEM without feature flag
        #[cfg(not(feature = "ml-kem"))]
        {
            let result = _provider.generate_keypair(Algorithm::MlKem512, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("ML-KEM implementations require 'ml-kem' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }

        // Test DAWN without feature flag
        #[cfg(not(feature = "dawn"))]
        {
            let result = _provider.generate_keypair(Algorithm::Dawn, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("DAWN KEM implementation requires 'dawn' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }
    }

    #[test]
    fn test_provider_algorithm_routing() {
        let _provider = LibQKemProvider::new().unwrap();

        // Test that algorithms are properly routed
        #[cfg(feature = "ml-kem")]
        {
            let result = _provider.generate_keypair(Algorithm::MlKem512, None);
            // Should either succeed or return NotImplemented (depending on std feature)
            match result {
                Ok(_) => {
                    // Success case - this is expected with std feature
                }
                Err(Error::NotImplemented { .. }) => {
                    // Expected when std feature is not available
                }
                Err(Error::RandomGenerationFailed { .. }) => {
                    // Expected when std feature is not available for randomness generation
                }
                Err(e) => {
                    panic!("Unexpected error type: {:?}", e);
                }
            }
        }

        #[cfg(feature = "dawn")]
        {
            let result = _provider.generate_keypair(Algorithm::Dawn, None);
            // Should return NotImplemented since DAWN is not yet implemented
            assert!(result.is_err());
            if let Err(Error::NotImplemented { feature }) = result {
                assert!(feature.contains("DAWN KEM implementation not yet available"));
            } else {
                panic!("Expected NotImplemented error for DAWN");
            }
        }
    }

    #[test]
    fn test_provider_full_kem_cycle() {
        #[cfg(feature = "ml-kem")]
        {
            let provider = LibQKemProvider::new().unwrap();

            // Test full KEM cycle for ML-KEM-512
            let keypair = provider
                .generate_keypair(Algorithm::MlKem512, None)
                .unwrap();

            // Test encapsulation
            let (ciphertext, shared_secret1) = provider
                .encapsulate(Algorithm::MlKem512, &keypair.public_key, None)
                .unwrap();

            // Test decapsulation
            let shared_secret2 = provider
                .decapsulate(Algorithm::MlKem512, &keypair.secret_key, &ciphertext)
                .unwrap();

            // Verify shared secrets match
            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secrets should match"
            );

            // Verify sizes are correct
            assert_eq!(
                ciphertext.len(),
                768,
                "ML-KEM-512 ciphertext should be 768 bytes"
            );
            assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");
        }
    }
}
