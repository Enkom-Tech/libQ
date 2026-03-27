//! AEAD context implementation for lib-Q Core
//!
//! This module provides the AEAD context that handles authenticated encryption
//! operations with proper security validation.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};

use super::BaseContext;
use crate::api::{
    AeadOperations,
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
    HashOperations,
    KemOperations,
    SignatureOperations,
};
use crate::error::Result;
use crate::traits::{
    AeadKey,
    Nonce,
};

/// Wraps a concrete [`AeadOperations`] value as a [`CryptoProvider`] that only exposes AEAD.
#[cfg(feature = "alloc")]
pub struct AeadOperationsBridge {
    aead: Box<dyn AeadOperations + Send + Sync>,
}

#[cfg(feature = "alloc")]
impl CryptoProvider for AeadOperationsBridge {
    fn kem(&self) -> Option<&dyn KemOperations> {
        None
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn AeadOperations> {
        Some(self.aead.as_ref())
    }
}

/// AEAD context for authenticated encryption operations
#[cfg(feature = "alloc")]
pub struct AeadContext {
    inner: BaseContext<Self>,
}

#[cfg(feature = "alloc")]
impl AeadContext {
    /// Create an AEAD context with no provider configured.
    ///
    /// Operations return [`Error::ProviderNotConfigured`](crate::error::Error::ProviderNotConfigured)
    /// until you call [`set_provider`](Self::set_provider) or build via [`with_aead_operations`](Self::with_aead_operations).
    /// The `lib-q` crate provides `libq::aead::context()` wired to `lib-q-aead`.
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

    /// Create a new AEAD context backed by the given AEAD implementation only.
    ///
    /// The `lib-q` facade typically injects `lib_q_aead::LibQAeadProvider` this way so `lib-q-core`
    /// does not depend on `lib-q-aead`.
    pub fn with_aead_operations(aead: Box<dyn AeadOperations + Send + Sync>) -> Self {
        Self {
            inner: BaseContext::with_provider(Box::new(AeadOperationsBridge { aead })),
        }
    }

    /// Create a new AEAD context with the default provider
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
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("AEAD"),
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
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("AEAD"),
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
    use crate::api::{
        AeadOperations,
        CryptoProvider,
        HashOperations,
        KemOperations,
        SignatureOperations,
    };

    // Mock provider for testing
    struct MockAeadProvider;

    impl CryptoProvider for MockAeadProvider {
        fn kem(&self) -> Option<&dyn KemOperations> {
            None
        }
        fn signature(&self) -> Option<&dyn SignatureOperations> {
            None
        }
        fn hash(&self) -> Option<&dyn HashOperations> {
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
    fn test_aead_context_with_aead_operations_bridge() {
        let context = AeadContext::with_aead_operations(Box::new(MockAeadProvider));
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
        assert!(context.provider().unwrap().aead().is_some());
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
