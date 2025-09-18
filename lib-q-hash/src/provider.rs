//! lib-Q Hash Provider Implementation
//!
//! This module provides the LibQHashProvider that implements the HashOperations
//! trait and routes hash operations to the appropriate algorithm implementations
//! with proper security validation.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::ToString,
    vec::Vec,
};

use lib_q_core::api::{
    Algorithm,
    CryptoProvider,
    HashOperations,
};
use lib_q_core::error::{
    Error,
    Result,
};
use lib_q_core::security::SecurityValidator;

use crate::{
    algorithm_to_hash_algorithm,
    create_hash,
};

/// lib-Q hash provider implementation
///
/// This provider implements hash operations for lib-Q, including hash computation
/// with proper security validation and algorithm routing.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQHashProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for LibQHashProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibQHashProvider")
            .field("security_validator", &"<SecurityValidator>")
            .finish()
    }
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

    /// Get the security validator
    pub fn security_validator(&self) -> &SecurityValidator {
        &self.security_validator
    }
}

#[cfg(feature = "alloc")]
impl HashOperations for LibQHashProvider {
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, lib_q_core::api::AlgorithmCategory::Hash)?;

        // Validate input data
        self.security_validator.validate_message(data)?;

        // Map Algorithm to HashAlgorithm and create hash instance
        let hash_algorithm = algorithm_to_hash_algorithm(algorithm)?;
        let hasher = create_hash(hash_algorithm).map_err(|e| Error::InternalError {
            operation: "hash instance creation".to_string(),
            details: format!(
                "Failed to create hash instance for algorithm {:?}: {}",
                algorithm, e
            ),
        })?;

        // Use the hash method from the lib-q-core Hash trait
        lib_q_core::Hash::hash(&*hasher, data).map_err(|e| Error::InternalError {
            operation: "hash computation".to_string(),
            details: format!(
                "Failed to compute hash for algorithm {:?}: {}",
                algorithm, e
            ),
        })
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQHashProvider {
    fn kem(&self) -> Option<&dyn lib_q_core::api::KemOperations> {
        None
    }

    fn signature(&self) -> Option<&dyn lib_q_core::api::SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        Some(self)
    }

    fn aead(&self) -> Option<&dyn lib_q_core::api::AeadOperations> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = LibQHashProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");
    }

    #[test]
    fn test_provider_security_validator() {
        let provider = LibQHashProvider::new().unwrap();
        let _validator = provider.security_validator();
        // Security validator should be accessible
    }

    #[test]
    fn test_provider_unsupported_algorithm() {
        let provider = LibQHashProvider::new().unwrap();
        let result = HashOperations::hash(&provider, Algorithm::MlDsa65, b"test data");
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
    fn test_provider_algorithm_routing() {
        let provider = LibQHashProvider::new().unwrap();

        // Test SHA-3 algorithms
        let test_data = b"Hello, lib-Q!";

        let result = HashOperations::hash(&provider, Algorithm::Sha3_256, test_data);
        assert!(result.is_ok(), "SHA3-256 should work");
        if let Ok(hash) = result {
            assert_eq!(hash.len(), 32, "SHA3-256 should produce 32-byte hash");
        }

        let result = HashOperations::hash(&provider, Algorithm::Sha3_512, test_data);
        assert!(result.is_ok(), "SHA3-512 should work");
        if let Ok(hash) = result {
            assert_eq!(hash.len(), 64, "SHA3-512 should produce 64-byte hash");
        }

        // Test SHAKE algorithms
        let result = HashOperations::hash(&provider, Algorithm::Shake128, test_data);
        assert!(result.is_ok(), "SHAKE128 should work");
        if let Ok(hash) = result {
            assert_eq!(hash.len(), 16, "SHAKE128 should produce 16-byte hash");
        }

        let result = HashOperations::hash(&provider, Algorithm::Shake256, test_data);
        assert!(result.is_ok(), "SHAKE256 should work");
        if let Ok(hash) = result {
            assert_eq!(hash.len(), 32, "SHAKE256 should produce 32-byte hash");
        }
    }
}
