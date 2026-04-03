//! lib-Q KEM Provider Implementation
//!
//! This module provides the LibQKemProvider that implements the KemOperations
//! trait and routes KEM operations to the appropriate algorithm implementations
//! with proper security validation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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
#[cfg(all(feature = "alloc", any(feature = "ml-kem", feature = "dawn")))]
use lib_q_core::traits::Kem;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};
// Import HQC implementations
#[cfg(feature = "hqc")]
use lib_q_hqc::LibQHqcProvider;

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

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.generate_keypair(algorithm, randomness)
            }

            // DAWN KEM algorithms
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha512);
                kem.generate_keypair()
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta512);
                kem.generate_keypair()
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha1024);
                kem.generate_keypair()
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta1024);
                kem.generate_keypair()
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            #[cfg(not(feature = "dawn"))]
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => Err(Error::NotImplemented {
                feature: String::from("DAWN KEM implementations require 'dawn' feature flag"),
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

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.encapsulate(algorithm, public_key, randomness)
            }

            // DAWN KEM algorithms
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha512);
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta512);
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha1024);
                kem.encapsulate(public_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta1024);
                kem.encapsulate(public_key)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            #[cfg(not(feature = "dawn"))]
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => Err(Error::NotImplemented {
                feature: String::from("DAWN KEM implementations require 'dawn' feature flag"),
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

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.decapsulate(algorithm, secret_key, ciphertext)
            }

            // DAWN KEM algorithms
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha512);
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta512);
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha1024);
                kem.decapsulate(secret_key, ciphertext)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta1024);
                kem.decapsulate(secret_key, ciphertext)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            #[cfg(not(feature = "dawn"))]
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => Err(Error::NotImplemented {
                feature: String::from("DAWN KEM implementations require 'dawn' feature flag"),
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

            // HQC algorithms
            #[cfg(feature = "hqc")]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                let hqc_provider = LibQHqcProvider::new()?;
                hqc_provider.derive_public_key(algorithm, secret_key)
            }

            // DAWN KEM algorithms
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha512);
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta512 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta512);
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnAlpha1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Alpha1024);
                kem.derive_public_key(secret_key)
            }
            #[cfg(feature = "dawn")]
            Algorithm::DawnBeta1024 => {
                use lib_q_dawn::{
                    DawnKem,
                    DawnParameterSet,
                };
                let kem = DawnKem::new(DawnParameterSet::Beta1024);
                kem.derive_public_key(secret_key)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: String::from("ML-KEM implementations require 'ml-kem' feature flag"),
                })
            }
            #[cfg(not(feature = "cb-kem"))]
            Algorithm::CbKem348864 |
            Algorithm::CbKem460896 |
            Algorithm::CbKem6688128 |
            Algorithm::CbKem6960119 |
            Algorithm::CbKem8192128 => Err(Error::NotImplemented {
                feature: String::from("CB-KEM implementations require 'cb-kem' feature flag"),
            }),
            #[cfg(not(feature = "hqc"))]
            Algorithm::Hqc128 | Algorithm::Hqc192 | Algorithm::Hqc256 => {
                Err(Error::NotImplemented {
                    feature: String::from("HQC implementations require 'hqc' feature flag"),
                })
            }
            #[cfg(not(feature = "dawn"))]
            Algorithm::DawnAlpha512 |
            Algorithm::DawnBeta512 |
            Algorithm::DawnAlpha1024 |
            Algorithm::DawnBeta1024 => Err(Error::NotImplemented {
                feature: String::from("DAWN KEM implementations require 'dawn' feature flag"),
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
            let result = _provider.generate_keypair(Algorithm::DawnAlpha512, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("DAWN KEM implementations require 'dawn' feature flag"),
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
            use lib_q_dawn::DawnParameterSet;

            let result = _provider.generate_keypair(Algorithm::DawnAlpha512, None);
            // Should succeed with dawn feature enabled
            assert!(
                result.is_ok(),
                "DAWN Alpha512 should work with dawn feature"
            );
            let keypair = result.unwrap();
            let alpha512 = DawnParameterSet::Alpha512;
            assert_eq!(
                keypair.public_key.data.len(),
                alpha512.public_key_size(),
                "public key length must match lib-q-dawn Alpha512"
            );
            assert_eq!(
                keypair.secret_key.data.len(),
                alpha512.secret_key_size(),
                "secret key length must match lib-q-dawn Alpha512"
            );
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

        // Test full KEM cycle for DAWN-α-512
        #[cfg(feature = "dawn")]
        {
            use lib_q_dawn::DawnParameterSet;

            let alpha512 = DawnParameterSet::Alpha512;
            let provider = LibQKemProvider::new().unwrap();

            let keypair = provider
                .generate_keypair(Algorithm::DawnAlpha512, None)
                .unwrap();

            let (ciphertext, shared_secret1) = provider
                .encapsulate(Algorithm::DawnAlpha512, &keypair.public_key, None)
                .unwrap();

            let shared_secret2 = provider
                .decapsulate(Algorithm::DawnAlpha512, &keypair.secret_key, &ciphertext)
                .unwrap();

            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secrets should match"
            );

            assert_eq!(
                ciphertext.len(),
                alpha512.ciphertext_size(),
                "ciphertext length must match lib-q-dawn Alpha512"
            );
            assert_eq!(
                shared_secret1.len(),
                alpha512.shared_secret_size(),
                "shared secret length must match lib-q-dawn Alpha512"
            );
            assert_eq!(
                keypair.public_key.data.len(),
                alpha512.public_key_size(),
                "public key length must match lib-q-dawn Alpha512"
            );
            assert_eq!(
                keypair.secret_key.data.len(),
                alpha512.secret_key_size(),
                "secret key length must match lib-q-dawn Alpha512"
            );
        }
    }
}
