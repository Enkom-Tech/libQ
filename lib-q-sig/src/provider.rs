//! lib-Q Signature Provider Implementation
//!
//! This module provides the `LibQSignatureProvider` that implements the `SignatureOperations`
//! trait and routes signature operations to the appropriate algorithm implementations
//! with comprehensive security validation.
//!
//! ## Architecture
//!
//! The `LibQSignatureProvider` serves as the central routing hub for all signature operations:
//! - **Algorithm Routing**: Routes operations to the correct algorithm implementation
//! - **Security Validation**: Validates all inputs using `SecurityValidator`
//! - **Feature Flag Handling**: Gracefully handles missing feature flags
//! - **Provider Integration**: Implements `CryptoProvider` for lib-q-core integration
//!
//! ## Security Features
//!
//! - **Input Validation**: All inputs are validated before processing
//! - **Algorithm Category Validation**: Ensures only signature algorithms are processed
//! - **Key Size Validation**: Validates key sizes against algorithm requirements
//! - **Randomness Validation**: Validates randomness quality and size
//! - **Message Validation**: Validates message content and size
//! - **Signature Validation**: Validates signature format and size
//!
//! ## Supported Operations
//!
//! - **Key Generation**: Generates keypairs for all supported algorithms
//! - **Signing**: Creates signatures with proper randomness handling
//! - **Verification**: Verifies signatures with comprehensive validation
//!
//! ## Algorithm Support
//!
//! The provider supports all NIST-approved signature algorithms:
//! - ML-DSA (CRYSTALS-ML-DSA): Levels 1, 3, 4
//! - FN-DSA (FIPS 206): Levels 1, 5
//! - SLH-DSA (SPHINCS+): Levels 1, 3, 5

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(
    feature = "alloc",
    not(feature = "std"),
    any(
        not(feature = "ml-dsa"),
        not(feature = "fn-dsa"),
        not(feature = "slh-dsa"),
    ),
))]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use lib_q_core::api::{
    Algorithm,
    CryptoProvider,
    SignatureOperations,
};
#[cfg(feature = "alloc")]
use lib_q_core::error::{
    Error,
    Result,
};
#[cfg(feature = "alloc")]
use lib_q_core::security::SecurityValidator;
#[cfg(all(feature = "alloc", any(feature = "ml-dsa", feature = "fn-dsa")))]
use lib_q_core::traits::Signature;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};

#[cfg(feature = "fn-dsa")]
use crate::fn_dsa::{
    FnDsa,
    FnDsa512,
    FnDsa1024,
};
// Import algorithm implementations
#[cfg(feature = "ml-dsa")]
use crate::ml_dsa::MlDsa;
#[cfg(feature = "slh-dsa")]
use crate::slh_dsa::SlhDsa;

/// lib-Q signature provider implementation
///
/// This provider implements signature operations for lib-Q, including key generation,
/// signing, and verification with proper security validation and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQSignatureProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl LibQSignatureProvider {
    /// Create a new signature provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQSignatureProvider with security validation initialized.
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
impl SignatureOperations for LibQSignatureProvider {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        // Validate algorithm category
        self.security_validator.validate_algorithm_category(
            algorithm,
            lib_q_core::api::AlgorithmCategory::Signature,
        )?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // ML-DSA algorithms
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = MlDsa::ml_dsa_44();
                if let Some(rng) = randomness {
                    // Use provided randomness
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.generate_keypair_with_randomness(rng_array)
                } else {
                    ml_dsa.generate_keypair()
                }
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = MlDsa::ml_dsa_65();
                if let Some(rng) = randomness {
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.generate_keypair_with_randomness(rng_array)
                } else {
                    ml_dsa.generate_keypair()
                }
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = MlDsa::ml_dsa_87();
                if let Some(rng) = randomness {
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.generate_keypair_with_randomness(rng_array)
                } else {
                    ml_dsa.generate_keypair()
                }
            }

            // FN-DSA algorithms
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa => {
                let fn_dsa = FnDsa::level1();
                fn_dsa.generate_keypair()
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa512 => {
                let fn_dsa = FnDsa512::new();
                fn_dsa.generate_keypair()
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa1024 => {
                let fn_dsa = FnDsa1024::new();
                fn_dsa.generate_keypair()
            }

            // SLH-DSA algorithms
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaSha256128fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaSha256192fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaSha256256fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaShake256128fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaShake256192fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaShake256256fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.generate_keypair_for_algorithm(algorithm, randomness)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA implementations require 'ml-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "fn-dsa"))]
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(Error::NotImplemented {
                    feature: "FN-DSA implementations require 'fn-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "slh-dsa"))]
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(Error::NotImplemented {
                feature: "SLH-DSA implementations require 'slh-dsa' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for signature operations",
            }),
        }
    }

    fn sign(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator.validate_algorithm_category(
            algorithm,
            lib_q_core::api::AlgorithmCategory::Signature,
        )?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate message
        self.security_validator.validate_message(message)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        match algorithm {
            // ML-DSA algorithms
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = MlDsa::ml_dsa_44();
                if let Some(rng) = randomness {
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.sign_with_randomness(secret_key, message, rng_array)
                } else {
                    ml_dsa.sign(secret_key, message)
                }
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = MlDsa::ml_dsa_65();
                if let Some(rng) = randomness {
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.sign_with_randomness(secret_key, message, rng_array)
                } else {
                    ml_dsa.sign(secret_key, message)
                }
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = MlDsa::ml_dsa_87();
                if let Some(rng) = randomness {
                    let rng_array: [u8; 32] =
                        rng.try_into().map_err(|_| Error::InvalidKeySize {
                            expected: 32,
                            actual: rng.len(),
                        })?;
                    ml_dsa.sign_with_randomness(secret_key, message, rng_array)
                } else {
                    ml_dsa.sign(secret_key, message)
                }
            }

            // FN-DSA algorithms
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa => {
                let fn_dsa = FnDsa::level1();
                fn_dsa.sign(secret_key, message)
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa512 => {
                let fn_dsa = FnDsa512::new();
                fn_dsa.sign(secret_key, message)
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa1024 => {
                let fn_dsa = FnDsa1024::new();
                fn_dsa.sign(secret_key, message)
            }

            // SLH-DSA algorithms
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.sign_for_algorithm(algorithm, secret_key, message, randomness)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA implementations require 'ml-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "fn-dsa"))]
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(Error::NotImplemented {
                    feature: "FN-DSA implementations require 'fn-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "slh-dsa"))]
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(Error::NotImplemented {
                feature: "SLH-DSA implementations require 'slh-dsa' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for signature operations",
            }),
        }
    }

    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        // Validate algorithm category
        self.security_validator.validate_algorithm_category(
            algorithm,
            lib_q_core::api::AlgorithmCategory::Signature,
        )?;

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate message
        self.security_validator.validate_message(message)?;

        // Validate signature
        self.security_validator
            .validate_signature(algorithm, signature)?;

        // Route to specific algorithm implementation
        match algorithm {
            // ML-DSA algorithms
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = MlDsa::ml_dsa_44();
                ml_dsa.verify(public_key, message, signature)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = MlDsa::ml_dsa_65();
                ml_dsa.verify(public_key, message, signature)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = MlDsa::ml_dsa_87();
                ml_dsa.verify(public_key, message, signature)
            }

            // FN-DSA algorithms
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa => {
                let fn_dsa = FnDsa::level1();
                fn_dsa.verify(public_key, message, signature)
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa512 => {
                let fn_dsa = FnDsa512::new();
                fn_dsa.verify(public_key, message, signature)
            }
            #[cfg(feature = "fn-dsa")]
            Algorithm::FnDsa1024 => {
                let fn_dsa = FnDsa1024::new();
                fn_dsa.verify(public_key, message, signature)
            }

            // SLH-DSA algorithms
            #[cfg(feature = "slh-dsa")]
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => {
                let slh_dsa = SlhDsa::new();
                slh_dsa.verify_for_algorithm(algorithm, public_key, message, signature)
            }

            // Handle missing feature flags
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA implementations require 'ml-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "fn-dsa"))]
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(Error::NotImplemented {
                    feature: "FN-DSA implementations require 'fn-dsa' feature flag".to_string(),
                })
            }
            #[cfg(not(feature = "slh-dsa"))]
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(Error::NotImplemented {
                feature: "SLH-DSA implementations require 'slh-dsa' feature flag".to_string(),
            }),

            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for signature operations",
            }),
        }
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQSignatureProvider {
    fn kem(&self) -> Option<&dyn lib_q_core::api::KemOperations> {
        None
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        Some(self)
    }

    fn hash(&self) -> Option<&dyn lib_q_core::api::HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn lib_q_core::api::AeadOperations> {
        None
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = LibQSignatureProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_security_validator() {
        let provider = LibQSignatureProvider::new().unwrap();
        let _validator = provider.security_validator();
        // Security validator should be accessible
        // Security validator is accessible
    }

    #[test]
    fn test_provider_unsupported_algorithm() {
        let provider = LibQSignatureProvider::new().unwrap();
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
        let _provider = LibQSignatureProvider::new().unwrap();

        // Test ML-DSA without feature flag
        #[cfg(not(feature = "ml-dsa"))]
        {
            let result = _provider.generate_keypair(Algorithm::MlDsa65, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("ML-DSA implementations require 'ml-dsa' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }

        // Test FN-DSA without feature flag
        #[cfg(not(feature = "fn-dsa"))]
        {
            let result = _provider.generate_keypair(Algorithm::FnDsa512, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("FN-DSA implementations require 'fn-dsa' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }

        // Test SLH-DSA without feature flag
        #[cfg(not(feature = "slh-dsa"))]
        {
            let result = _provider.generate_keypair(Algorithm::SlhDsaSha256128fRobust, None);
            assert!(
                result.is_err(),
                "Should return error when feature flag is not enabled"
            );

            if let Err(Error::NotImplemented { feature }) = result {
                assert!(
                    feature.contains("SLH-DSA implementations require 'slh-dsa' feature flag"),
                    "Error should mention feature flag requirement"
                );
            } else {
                panic!("Expected NotImplemented error");
            }
        }
    }

    #[test]
    fn test_provider_algorithm_routing() {
        let provider = LibQSignatureProvider::new().unwrap();

        // Test that algorithms are properly routed
        #[cfg(feature = "ml-dsa")]
        {
            let result = provider.generate_keypair(Algorithm::MlDsa65, None);
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

        #[cfg(feature = "fn-dsa")]
        {
            let result = provider.generate_keypair(Algorithm::FnDsa512, None);
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

        #[cfg(feature = "slh-dsa")]
        {
            let result = provider.generate_keypair(Algorithm::SlhDsaSha256128fRobust, None);
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
    }

    #[test]
    fn test_provider_sign_rejects_non_signature_algorithm() {
        let provider = LibQSignatureProvider::new().unwrap();
        let secret_key = SigSecretKey::new(Vec::new());
        let result = provider.sign(Algorithm::Sha3_256, &secret_key, b"message", None);
        assert!(
            matches!(result, Err(Error::InvalidAlgorithm { .. })),
            "sign should reject non-signature algorithms before key validation"
        );
    }

    #[test]
    fn test_provider_verify_rejects_non_signature_algorithm() {
        let provider = LibQSignatureProvider::new().unwrap();
        let public_key = SigPublicKey::new(Vec::new());
        let result = provider.verify(Algorithm::Sha3_256, &public_key, b"message", b"sig");
        assert!(
            matches!(result, Err(Error::InvalidAlgorithm { .. })),
            "verify should reject non-signature algorithms before key/signature validation"
        );
    }

    #[test]
    fn test_crypto_provider_exposes_signature_only() {
        let provider = LibQSignatureProvider::new().unwrap();
        assert!(provider.signature().is_some());
        assert!(provider.kem().is_none());
        assert!(provider.hash().is_none());
        assert!(provider.aead().is_none());
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn test_provider_ml_dsa44_with_explicit_randomness_round_trip() {
        use lib_q_core::Utils;

        let provider = LibQSignatureProvider::new().unwrap();
        let message = b"provider ml-dsa44 explicit randomness";
        let key_randomness = Utils::random_bytes(32).expect("test randomness generation failed");
        let signing_randomness =
            Utils::random_bytes(32).expect("test randomness generation failed");

        let keypair = provider
            .generate_keypair(Algorithm::MlDsa44, Some(&key_randomness))
            .expect("key generation with explicit randomness should succeed");

        let signature = provider
            .sign(
                Algorithm::MlDsa44,
                keypair.secret_key(),
                message,
                Some(&signing_randomness),
            )
            .expect("signing with explicit randomness should succeed");

        let is_valid = provider
            .verify(
                Algorithm::MlDsa44,
                keypair.public_key(),
                message,
                &signature,
            )
            .expect("verification should succeed");
        assert!(
            is_valid,
            "provider should verify its own ML-DSA-44 signatures"
        );
    }
}
