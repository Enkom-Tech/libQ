//! KEM context implementation for lib-Q Core
//!
//! This module provides the KEM context that handles key encapsulation
//! mechanism operations with proper security validation.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};

use super::BaseContext;
#[cfg(test)]
use crate::api::KemOperations;
use crate::api::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
};
use crate::error::Result;
use crate::traits::{
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
};

/// KEM context for key encapsulation operations
#[cfg(feature = "alloc")]
pub struct KemContext {
    inner: BaseContext<Self>,
}

#[cfg(feature = "alloc")]
impl KemContext {
    /// Create a new KEM context with no provider
    pub fn new() -> Self {
        Self {
            inner: BaseContext::new(),
        }
    }

    /// Create a new KEM context with a provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: BaseContext::with_provider(provider),
        }
    }

    /// Create a new KEM context with the default provider
    #[cfg(feature = "alloc")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: match crate::providers::LibQCryptoProvider::new() {
                Ok(provider) => BaseContext::with_provider(Box::new(provider)),
                Err(_) => BaseContext::new(),
            },
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

    /// Generate a keypair for the specified algorithm
    pub fn generate_keypair(
        &mut self,
        algorithm: Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        self.inner.ensure_initialized()?;

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a KEM algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.generate_keypair(algorithm, randomness),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("KEM"),
            }),
        }
    }

    /// Encapsulate a key using the given public key
    pub fn encapsulate(
        &self,
        algorithm: Algorithm,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("encapsulate"),
                reason: String::from("Context not initialized"),
            });
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a KEM algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.encapsulate(algorithm, public_key, randomness),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("KEM"),
            }),
        }
    }

    /// Decapsulate a key using the given secret key and ciphertext
    pub fn decapsulate(
        &self,
        algorithm: Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("decapsulate"),
                reason: String::from("Context not initialized"),
            });
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Kem {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a KEM algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.kem()) {
            Some(kem_ops) => kem_ops.decapsulate(algorithm, secret_key, ciphertext),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("KEM"),
            }),
        }
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
}

#[cfg(feature = "alloc")]
impl Default for KemContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::CryptoProvider;

    // Mock provider for testing
    struct MockKemProvider;

    impl CryptoProvider for MockKemProvider {
        fn kem(&self) -> Option<&dyn KemOperations> {
            Some(self)
        }
        fn signature(&self) -> Option<&dyn crate::api::SignatureOperations> {
            None
        }
        fn hash(&self) -> Option<&dyn crate::api::HashOperations> {
            None
        }
        fn aead(&self) -> Option<&dyn crate::api::AeadOperations> {
            None
        }
    }

    impl KemOperations for MockKemProvider {
        fn generate_keypair(
            &self,
            _algorithm: Algorithm,
            _randomness: Option<&[u8]>,
        ) -> Result<KemKeypair> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock KEM operations not implemented".to_string(),
            })
        }

        fn encapsulate(
            &self,
            _algorithm: Algorithm,
            _public_key: &KemPublicKey,
            _randomness: Option<&[u8]>,
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock KEM operations not implemented".to_string(),
            })
        }

        fn decapsulate(
            &self,
            _algorithm: Algorithm,
            _secret_key: &KemSecretKey,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock KEM operations not implemented".to_string(),
            })
        }

        fn derive_public_key(
            &self,
            _algorithm: Algorithm,
            _secret_key: &KemSecretKey,
        ) -> Result<KemPublicKey> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock KEM operations not implemented".to_string(),
            })
        }
    }

    #[test]
    fn test_kem_context_creation() {
        let context = KemContext::new();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_kem_context_with_provider() {
        let provider = Box::new(MockKemProvider);
        let context = KemContext::with_provider(provider);
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_kem_context_provider_management() {
        let mut context = KemContext::new();
        assert!(context.provider().is_none());

        let provider = Box::new(MockKemProvider);
        context.set_provider(provider);
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_kem_context_initialization() {
        let mut context = KemContext::new();
        assert!(!context.is_initialized());

        // Should initialize automatically on first operation
        let result = context.generate_keypair(Algorithm::MlKem512, None);
        assert!(result.is_err()); // Will fail due to no provider, but context should be initialized
        assert!(context.is_initialized());
    }

    #[test]
    fn test_kem_context_algorithm_validation() {
        let mut context = KemContext::new();

        // Try to use a non-KEM algorithm
        let result = context.generate_keypair(Algorithm::Sha3_256, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::InvalidAlgorithm { .. }) = result {
            // Expected error
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }
}
