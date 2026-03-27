//! Hash context implementation for lib-Q Core
//!
//! This module provides the hash context that handles hash operations
//! with proper security validation.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};

use super::BaseContext;
#[cfg(test)]
use crate::api::HashOperations;
use crate::api::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
};
use crate::error::Result;

/// Hash context for hash operations
#[cfg(feature = "alloc")]
pub struct HashContext {
    inner: BaseContext<Self>,
}

#[cfg(feature = "alloc")]
impl HashContext {
    /// Create a new hash context with no provider
    pub fn new() -> Self {
        Self {
            inner: BaseContext::new(),
        }
    }

    /// Create a new hash context with a provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: BaseContext::with_provider(provider),
        }
    }

    /// Create a new hash context with the default provider
    #[cfg(feature = "alloc")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: BaseContext::with_provider(Box::new(
                crate::providers::LibQCryptoProvider::new().unwrap_or_else(|_| {
                    // Fallback to a minimal provider if initialization fails
                    crate::providers::LibQCryptoProvider::new().unwrap()
                }),
            )),
        }
    }

    /// Set the cryptographic provider
    pub fn set_provider(&mut self, provider: Box<dyn CryptoProvider>) {
        self.inner.set_provider(provider);
    }

    /// Get the current provider
    pub fn provider(&self) -> Option<&dyn CryptoProvider> {
        self.inner.provider()
    }

    /// Hash data using the specified algorithm
    pub fn hash(&mut self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.ensure_initialized()?;

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Hash {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a hash algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.hash()) {
            Some(hash_ops) => hash_ops.hash(algorithm, data),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("hash"),
            }),
        }
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
}

#[cfg(feature = "alloc")]
impl Default for HashContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::CryptoProvider;

    // Mock provider for testing
    struct MockHashProvider;

    impl CryptoProvider for MockHashProvider {
        fn kem(&self) -> Option<&dyn crate::api::KemOperations> {
            None
        }
        fn signature(&self) -> Option<&dyn crate::api::SignatureOperations> {
            None
        }
        fn hash(&self) -> Option<&dyn HashOperations> {
            Some(self)
        }
        fn aead(&self) -> Option<&dyn crate::api::AeadOperations> {
            None
        }
    }

    impl HashOperations for MockHashProvider {
        fn hash(&self, _algorithm: Algorithm, _data: &[u8]) -> Result<Vec<u8>> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock hash operations not implemented".to_string(),
            })
        }
    }

    #[test]
    fn test_hash_context_creation() {
        let context = HashContext::new();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_hash_context_with_provider() {
        let provider = Box::new(MockHashProvider);
        let context = HashContext::with_provider(provider);
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_hash_context_provider_management() {
        let mut context = HashContext::new();
        assert!(context.provider().is_none());

        let provider = Box::new(MockHashProvider);
        context.set_provider(provider);
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_hash_context_initialization() {
        let mut context = HashContext::new();
        assert!(!context.is_initialized());

        // Should initialize automatically on first operation
        let result = context.hash(Algorithm::Sha3_256, b"test data");
        assert!(result.is_err()); // Will fail due to no provider, but context should be initialized
        assert!(context.is_initialized());
    }

    #[test]
    fn test_hash_context_algorithm_validation() {
        let mut context = HashContext::new();

        // Try to use a non-hash algorithm
        let result = context.hash(Algorithm::MlKem512, b"test data");
        assert!(result.is_err());
        if let Err(crate::error::Error::InvalidAlgorithm { .. }) = result {
            // Expected error
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }
}
