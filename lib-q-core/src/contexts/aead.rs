//! AEAD context implementation for lib-Q Core
//!
//! This module provides the AEAD context that handles authenticated encryption
//! operations with proper security validation.

use super::BaseContext;
#[cfg(test)]
use crate::api::AeadOperations;
use crate::api::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
};
use crate::error::Result;
use crate::traits::{
    AeadKey,
    Nonce,
};

/// AEAD context for authenticated encryption operations
#[cfg(feature = "alloc")]
pub struct AeadContext {
    inner: BaseContext<Self>,
}

#[cfg(feature = "alloc")]
impl AeadContext {
    /// Create a new AEAD context with no provider
    pub fn new() -> Self {
        Self {
            inner: BaseContext::new(),
        }
    }

    /// Create a new AEAD context with a provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: BaseContext::with_provider(provider),
        }
    }

    /// Create a new AEAD context with the default provider
    #[cfg(feature = "std")]
    pub fn with_default_provider() -> Self {
        Self {
            inner: BaseContext::with_provider(Box::new(crate::api::DefaultCryptoProvider)),
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

    /// Encrypt data using the specified algorithm
    pub fn encrypt(
        &mut self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.inner.ensure_initialized()?;

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Aead {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not an AEAD algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.aead()) {
            Some(aead_ops) => aead_ops.encrypt(algorithm, key, nonce, plaintext, associated_data),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("AEAD operations - no provider configured"),
            }),
        }
    }

    /// Decrypt data using the specified algorithm
    pub fn decrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("decrypt"),
                reason: String::from("Context not initialized"),
            });
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Aead {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not an AEAD algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.aead()) {
            Some(aead_ops) => aead_ops.decrypt(algorithm, key, nonce, ciphertext, associated_data),
            None => Err(crate::error::Error::NotImplemented {
                feature: String::from("AEAD operations - no provider configured"),
            }),
        }
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
}

#[cfg(feature = "alloc")]
impl Default for AeadContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::CryptoProvider;

    // Mock provider for testing
    struct MockAeadProvider;

    impl CryptoProvider for MockAeadProvider {
        fn kem(&self) -> Option<&dyn crate::api::KemOperations> {
            None
        }
        fn signature(&self) -> Option<&dyn crate::api::SignatureOperations> {
            None
        }
        fn hash(&self) -> Option<&dyn crate::api::HashOperations> {
            None
        }
        fn aead(&self) -> Option<&dyn AeadOperations> {
            Some(self)
        }
    }

    impl AeadOperations for MockAeadProvider {
        fn encrypt(
            &self,
            _algorithm: Algorithm,
            _key: &AeadKey,
            _nonce: &Nonce,
            _plaintext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock AEAD operations not implemented".to_string(),
            })
        }

        fn decrypt(
            &self,
            _algorithm: Algorithm,
            _key: &AeadKey,
            _nonce: &Nonce,
            _ciphertext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock AEAD operations not implemented".to_string(),
            })
        }
    }

    #[test]
    fn test_aead_context_creation() {
        let context = AeadContext::new();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_aead_context_with_provider() {
        let provider = Box::new(MockAeadProvider);
        let context = AeadContext::with_provider(provider);
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_aead_context_provider_management() {
        let mut context = AeadContext::new();
        assert!(context.provider().is_none());

        let provider = Box::new(MockAeadProvider);
        context.set_provider(provider);
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_aead_context_initialization() {
        let mut context = AeadContext::new();
        assert!(!context.is_initialized());

        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);

        // Should initialize automatically on first operation
        let result = context.encrypt(Algorithm::Saturnin, &key, &nonce, b"test data", None);
        assert!(result.is_err()); // Will fail due to no provider, but context should be initialized
        assert!(context.is_initialized());
    }

    #[test]
    fn test_aead_context_algorithm_validation() {
        let mut context = AeadContext::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);

        // Try to use a non-AEAD algorithm
        let result = context.encrypt(Algorithm::MlKem512, &key, &nonce, b"test data", None);
        assert!(result.is_err());
        if let Err(crate::error::Error::InvalidAlgorithm { .. }) = result {
            // Expected error
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }
}
