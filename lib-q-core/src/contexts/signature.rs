//! Signature context implementation for lib-Q Core
//!
//! This module provides the signature context that handles digital signature
//! operations with proper security validation.

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};

use super::BaseContext;
#[cfg(test)]
use crate::api::SignatureOperations;
use crate::api::{
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
};
use crate::error::Result;
use crate::traits::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};

/// Signature context for digital signature operations
#[cfg(feature = "alloc")]
pub struct SignatureContext {
    inner: BaseContext<Self>,
}

#[cfg(feature = "alloc")]
impl SignatureContext {
    /// Create a new signature context with no provider
    pub fn new() -> Self {
        Self {
            inner: BaseContext::new(),
        }
    }

    /// Create a new signature context with a provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            inner: BaseContext::with_provider(provider),
        }
    }

    /// Create a new signature context with the default provider
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
    ) -> Result<SigKeypair> {
        self.inner.ensure_initialized()?;

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Signature {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a signature algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.generate_keypair(algorithm, randomness),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("signature"),
            }),
        }
    }

    /// Sign a message using the given secret key
    pub fn sign(
        &self,
        algorithm: Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("sign"),
                reason: String::from("Context not initialized"),
            });
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Signature {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a signature algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.sign(algorithm, secret_key, message, randomness),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("signature"),
            }),
        }
    }

    /// Verify a signature for the given message and public key
    pub fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        if !self.inner.is_initialized() {
            return Err(crate::error::Error::InvalidState {
                operation: String::from("verify"),
                reason: String::from("Context not initialized"),
            });
        }

        // Validate algorithm category
        if algorithm.category() != AlgorithmCategory::Signature {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a signature algorithm",
            });
        }

        // Use provider if available
        match self.inner.provider().and_then(|p| p.signature()) {
            Some(sig_ops) => sig_ops.verify(algorithm, public_key, message, signature),
            None => Err(crate::error::Error::ProviderNotConfigured {
                operation: String::from("signature"),
            }),
        }
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
}

#[cfg(feature = "alloc")]
impl Default for SignatureContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::CryptoProvider;

    // Mock provider for testing
    struct MockSignatureProvider;

    impl CryptoProvider for MockSignatureProvider {
        fn kem(&self) -> Option<&dyn crate::api::KemOperations> {
            None
        }
        fn signature(&self) -> Option<&dyn SignatureOperations> {
            Some(self)
        }
        fn hash(&self) -> Option<&dyn crate::api::HashOperations> {
            None
        }
        fn aead(&self) -> Option<&dyn crate::api::AeadOperations> {
            None
        }
    }

    impl SignatureOperations for MockSignatureProvider {
        fn generate_keypair(
            &self,
            _algorithm: Algorithm,
            _randomness: Option<&[u8]>,
        ) -> Result<SigKeypair> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock signature operations not implemented".to_string(),
            })
        }

        fn sign(
            &self,
            _algorithm: Algorithm,
            _secret_key: &SigSecretKey,
            _message: &[u8],
            _randomness: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock signature operations not implemented".to_string(),
            })
        }

        fn verify(
            &self,
            _algorithm: Algorithm,
            _public_key: &SigPublicKey,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool> {
            Err(crate::error::Error::NotImplemented {
                feature: "Mock signature operations not implemented".to_string(),
            })
        }
    }

    #[test]
    fn test_signature_context_creation() {
        let context = SignatureContext::new();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_signature_context_with_provider() {
        let provider = Box::new(MockSignatureProvider);
        let context = SignatureContext::with_provider(provider);
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_signature_context_provider_management() {
        let mut context = SignatureContext::new();
        assert!(context.provider().is_none());

        let provider = Box::new(MockSignatureProvider);
        context.set_provider(provider);
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_signature_context_initialization() {
        let mut context = SignatureContext::new();
        assert!(!context.is_initialized());

        // Should initialize automatically on first operation
        let result = context.generate_keypair(Algorithm::MlDsa44, None);
        assert!(result.is_err()); // Will fail due to no provider, but context should be initialized
        assert!(context.is_initialized());
    }

    #[test]
    fn test_signature_context_algorithm_validation() {
        let mut context = SignatureContext::new();

        // Try to use a non-signature algorithm
        let result = context.generate_keypair(Algorithm::Sha3_256, None);
        assert!(result.is_err());
        if let Err(crate::error::Error::InvalidAlgorithm { .. }) = result {
            // Expected error
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }
}
