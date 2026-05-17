//! Hash provider implementation
//!
//! This module provides the LibQHashProvider that implements hash operations
//! with proper security validation and algorithm routing.

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use crate::api::{
    Algorithm,
    HashOperations,
};
use crate::error::Result;
use crate::security::SecurityValidator;

/// lib-Q hash provider implementation
///
/// This provider implements hash operations for lib-Q with proper security validation
/// and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQHashProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl LibQHashProvider {
    /// Create a new hash provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQHashProvider with security validation initialized.
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
impl HashOperations for LibQHashProvider {
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Hash)?;

        // Validate data
        self.security_validator.validate_hash_input(data)?;

        // Route to specific algorithm implementation
        // Note: Actual implementations are provided by the main lib-q crate
        match algorithm {
            Algorithm::Sha3_224 |
            Algorithm::Sha3_256 |
            Algorithm::Sha3_384 |
            Algorithm::Sha3_512 => Err(crate::error::Error::NotImplemented {
                feature: "SHA3 implementations are provided by the main lib-q crate".to_string(),
            }),
            Algorithm::Shake128 | Algorithm::Shake256 => Err(crate::error::Error::NotImplemented {
                feature: "SHAKE implementations are provided by the main lib-q crate".to_string(),
            }),
            Algorithm::CShake128 | Algorithm::CShake256 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "cSHAKE implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Kmac128 | Algorithm::Kmac256 => Err(crate::error::Error::NotImplemented {
                feature: "KMAC implementations are provided by the main lib-q crate".to_string(),
            }),
            Algorithm::TupleHash128 | Algorithm::TupleHash256 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "TupleHash implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::ParallelHash128 | Algorithm::ParallelHash256 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "ParallelHash implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Keccak224 |
            Algorithm::Keccak256 |
            Algorithm::Keccak384 |
            Algorithm::Keccak512 => Err(crate::error::Error::NotImplemented {
                feature: "Keccak implementations are provided by the main lib-q crate".to_string(),
            }),
            Algorithm::Kt128 | Algorithm::Kt256 => Err(crate::error::Error::NotImplemented {
                feature: "KT128/KT256 (lib-q-k12) is provided by the lib-q-hash / lib-q meta crate"
                    .to_string(),
            }),
            Algorithm::TurboShake128 | Algorithm::TurboShake256 => {
                Err(crate::error::Error::NotImplemented {
                    feature: "TurboShake implementations are provided by the main lib-q crate"
                        .to_string(),
                })
            }
            Algorithm::Sha224 |
            Algorithm::Sha256 |
            Algorithm::Sha384 |
            Algorithm::Sha512 |
            Algorithm::Sha512_224 |
            Algorithm::Sha512_256 => Err(crate::error::Error::NotImplemented {
                feature: "SHA-2 implementations are provided by the main lib-q crate".to_string(),
            }),
            _ => Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported for hash operations",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_provider_creation() {
        let provider = LibQHashProvider::new();
        assert!(
            provider.is_ok(),
            "LibQHashProvider should be created successfully"
        );
    }

    #[test]
    fn test_hash_provider_unsupported_algorithm() {
        let provider = LibQHashProvider::new().unwrap();
        let result = provider.hash(Algorithm::MlKem512, b"test data");
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
    fn test_hash_provider_supported_algorithm() {
        let provider = LibQHashProvider::new().unwrap();
        let result = provider.hash(Algorithm::Sha3_256, b"test data");
        assert!(
            result.is_err(),
            "Should return NotImplemented error for unimplemented algorithm"
        );

        if let Err(crate::error::Error::NotImplemented { .. }) = result {
            // Expected error type
        } else {
            panic!("Expected NotImplemented error");
        }
    }
}
