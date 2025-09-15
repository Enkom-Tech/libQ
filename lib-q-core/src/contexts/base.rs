//! Base context implementation for lib-Q Core
//!
//! This module provides the foundational context structure that all
//! cryptographic operation contexts inherit from.

use core::marker::PhantomData;

use crate::api::CryptoProvider;
use crate::error::Result;

/// Base context trait that all cryptographic contexts must implement
pub trait ContextOps {
    /// Initialize the context
    fn init(&mut self) -> Result<()>;

    /// Check if the context is initialized
    fn is_initialized(&self) -> bool;

    /// Get the provider (if any)
    fn provider(&self) -> Option<&dyn CryptoProvider>;

    /// Set the provider
    fn set_provider(&mut self, provider: Box<dyn CryptoProvider>);
}

/// Generic context wrapper that provides common functionality
#[cfg(feature = "alloc")]
pub struct BaseContext<T> {
    _phantom: PhantomData<T>,
    initialized: bool,
    provider: Option<Box<dyn CryptoProvider>>,
}

#[cfg(feature = "alloc")]
impl<T> BaseContext<T> {
    /// Create a new uninitialized context
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            initialized: false,
            provider: None,
        }
    }

    /// Create a new context with a provider
    pub fn with_provider(provider: Box<dyn CryptoProvider>) -> Self {
        Self {
            _phantom: PhantomData,
            initialized: false,
            provider: Some(provider),
        }
    }

    /// Initialize the context
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;
        Ok(())
    }

    /// Check if the context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the provider (if any)
    pub fn provider(&self) -> Option<&dyn CryptoProvider> {
        self.provider.as_deref()
    }

    /// Set the provider
    pub fn set_provider(&mut self, provider: Box<dyn CryptoProvider>) {
        self.provider = Some(provider);
    }

    /// Ensure the context is initialized
    pub fn ensure_initialized(&mut self) -> Result<()> {
        if !self.initialized {
            self.init()?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<T> Default for BaseContext<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Context builder for creating contexts with specific configurations
#[cfg(feature = "alloc")]
pub struct ContextBuilder<T> {
    provider: Option<Box<dyn CryptoProvider>>,
    _phantom: PhantomData<T>,
}

#[cfg(feature = "alloc")]
impl<T> ContextBuilder<T> {
    /// Create a new context builder
    pub fn new() -> Self {
        Self {
            provider: None,
            _phantom: PhantomData,
        }
    }

    /// Set the provider for the context
    pub fn with_provider(mut self, provider: Box<dyn CryptoProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Build the context
    pub fn build(self) -> BaseContext<T> {
        match self.provider {
            Some(provider) => BaseContext::with_provider(provider),
            None => BaseContext::new(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T> Default for ContextBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::CryptoProvider;

    // Mock provider for testing
    struct MockProvider;

    impl CryptoProvider for MockProvider {
        fn kem(&self) -> Option<&dyn crate::api::KemOperations> {
            None
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

    #[test]
    fn test_base_context_creation() {
        let context = BaseContext::<()>::new();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_base_context_with_provider() {
        let provider = Box::new(MockProvider);
        let context = BaseContext::<()>::with_provider(provider);
        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_base_context_initialization() {
        let mut context = BaseContext::<()>::new();
        assert!(!context.is_initialized());

        let result = context.init();
        assert!(result.is_ok());
        assert!(context.is_initialized());

        // Second initialization should be idempotent
        let result = context.init();
        assert!(result.is_ok());
        assert!(context.is_initialized());
    }

    #[test]
    fn test_base_context_provider_management() {
        let mut context = BaseContext::<()>::new();
        assert!(context.provider().is_none());

        let provider = Box::new(MockProvider);
        context.set_provider(provider);
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_context_builder() {
        let provider = Box::new(MockProvider);
        let context = ContextBuilder::<()>::new().with_provider(provider).build();

        assert!(!context.is_initialized());
        assert!(context.provider().is_some());
    }

    #[test]
    fn test_context_builder_default() {
        let context = ContextBuilder::<()>::default().build();
        assert!(!context.is_initialized());
        assert!(context.provider().is_none());
    }

    #[test]
    fn test_ensure_initialized() {
        let mut context = BaseContext::<()>::new();
        assert!(!context.is_initialized());

        let result = context.ensure_initialized();
        assert!(result.is_ok());
        assert!(context.is_initialized());

        // Second call should still work
        let result = context.ensure_initialized();
        assert!(result.is_ok());
        assert!(context.is_initialized());
    }
}
