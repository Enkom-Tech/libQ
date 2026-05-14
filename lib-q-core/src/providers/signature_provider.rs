//! Signature provider implementation
//!
//! This module provides the LibQSignatureProvider that implements signature operations
//! with proper security validation and algorithm routing.

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use crate::api::{
    Algorithm,
    SignatureOperations,
};
use crate::error::Result;
use crate::security::SecurityValidator;
use crate::traits::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};

/// lib-Q signature provider implementation
///
/// This provider implements signature operations for lib-Q, including key generation,
/// signing, and verification with proper security validation.
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
}

#[cfg(feature = "alloc")]
impl SignatureOperations for LibQSignatureProvider {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Signature)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "FN-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(crate::error::Error::NotImplemented {
                feature: "SLH-DSA implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
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
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Signature)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate message
        self.security_validator
            .validate_signature_message(message)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "FN-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(crate::error::Error::NotImplemented {
                feature: "SLH-DSA implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
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
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Signature)?;

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate message
        self.security_validator
            .validate_signature_message(message)?;

        // Validate signature
        self.security_validator
            .validate_signature(algorithm, signature)?;

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ML-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::FnDsa | Algorithm::FnDsa512 | Algorithm::FnDsa1024 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "FN-DSA implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::SlhDsaSha256128fRobust |
            Algorithm::SlhDsaSha256192fRobust |
            Algorithm::SlhDsaSha256256fRobust |
            Algorithm::SlhDsaShake256128fRobust |
            Algorithm::SlhDsaShake256192fRobust |
            Algorithm::SlhDsaShake256256fRobust => Err(crate::error::Error::NotImplemented {
                feature: "SLH-DSA implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for signature operations",
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_signature_provider_creation() {
        let provider = LibQSignatureProvider::new();
        assert!(
            provider.is_ok(),
            "LibQSignatureProvider should be created successfully"
        );
    }

    #[test]
    fn test_signature_provider_unsupported_algorithm() {
        let provider = LibQSignatureProvider::new().unwrap();
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
    fn test_signature_provider_feature_flag_handling() {
        let provider = LibQSignatureProvider::new().unwrap();

        // Test ML-DSA without feature flag
        let result = provider.generate_keypair(Algorithm::MlDsa65, None);
        assert!(
            result.is_err(),
            "Should return error when feature flag is not enabled"
        );

        if let Err(crate::error::Error::NotImplemented { feature }) = result {
            assert!(
                feature.contains("ML-DSA implementations are provided by the main lib-q crate"),
                "Error should mention that implementations are provided by main lib-q crate"
            );
        } else {
            panic!("Expected NotImplemented error");
        }
    }
}
