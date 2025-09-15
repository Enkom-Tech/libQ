//! Main lib-Q cryptographic provider implementation
//!
//! This module provides the main LibQCryptoProvider that implements
//! the CryptoProvider trait and delegates to specific operation providers.

use super::{
    LibQAeadProvider,
    LibQHashProvider,
    LibQKemProvider,
    LibQSignatureProvider,
};
use crate::api::{
    AeadOperations,
    CryptoProvider,
    HashOperations,
    KemOperations,
    SignatureOperations,
};
use crate::error::Result;

/// Main lib-Q cryptographic provider
///
/// This provider implements the CryptoProvider trait and delegates
/// to specific operation providers for each cryptographic operation type.
/// It serves as the main entry point for all lib-Q cryptographic operations.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct LibQCryptoProvider {
    kem_provider: LibQKemProvider,
    signature_provider: LibQSignatureProvider,
    hash_provider: LibQHashProvider,
    aead_provider: LibQAeadProvider,
}

// WASM-compatible version
#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct LibQCryptoProvider {
    // Placeholder for WASM environments
}

#[cfg(feature = "std")]
impl LibQCryptoProvider {
    /// Create a new lib-Q cryptographic provider
    ///
    /// # Returns
    ///
    /// A new instance of LibQCryptoProvider with all operation providers initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the operation providers fail to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            kem_provider: LibQKemProvider::new()?,
            signature_provider: LibQSignatureProvider::new()?,
            hash_provider: LibQHashProvider::new()?,
            aead_provider: LibQAeadProvider::new()?,
        })
    }

    /// Get the KEM provider
    pub fn kem_provider(&self) -> &LibQKemProvider {
        &self.kem_provider
    }

    /// Get the signature provider
    pub fn signature_provider(&self) -> &LibQSignatureProvider {
        &self.signature_provider
    }

    /// Get the hash provider
    pub fn hash_provider(&self) -> &LibQHashProvider {
        &self.hash_provider
    }

    /// Get the AEAD provider
    pub fn aead_provider(&self) -> &LibQAeadProvider {
        &self.aead_provider
    }
}

// WASM-compatible implementation
#[cfg(not(feature = "std"))]
impl LibQCryptoProvider {
    /// Create a new lib-Q cryptographic provider (WASM version)
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[cfg(feature = "std")]
impl Default for LibQCryptoProvider {
    fn default() -> Self {
        Self::new().expect("Failed to create default LibQCryptoProvider")
    }
}

#[cfg(not(feature = "std"))]
impl Default for LibQCryptoProvider {
    fn default() -> Self {
        Self::new().expect("Failed to create default LibQCryptoProvider")
    }
}

#[cfg(feature = "std")]
impl CryptoProvider for LibQCryptoProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(&self.kem_provider)
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        Some(&self.signature_provider)
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        Some(&self.hash_provider)
    }

    fn aead(&self) -> Option<&dyn AeadOperations> {
        Some(&self.aead_provider)
    }
}

#[cfg(not(feature = "std"))]
impl CryptoProvider for LibQCryptoProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        None // Placeholder for WASM
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        None // Placeholder for WASM
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        None // Placeholder for WASM
    }

    fn aead(&self) -> Option<&dyn AeadOperations> {
        None // Placeholder for WASM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libq_provider_creation() {
        let provider = LibQCryptoProvider::new();
        assert!(
            provider.is_ok(),
            "LibQCryptoProvider should be created successfully"
        );
    }

    #[test]
    fn test_libq_provider_default() {
        let provider = LibQCryptoProvider::default();
        assert!(provider.kem().is_some(), "KEM provider should be available");
        assert!(
            provider.signature().is_some(),
            "Signature provider should be available"
        );
        assert!(
            provider.hash().is_some(),
            "Hash provider should be available"
        );
        assert!(
            provider.aead().is_some(),
            "AEAD provider should be available"
        );
    }

    #[test]
    fn test_libq_provider_operations() {
        let provider = LibQCryptoProvider::new().unwrap();

        // Test that all operation providers are accessible
        assert!(provider.kem().is_some());
        assert!(provider.signature().is_some());
        assert!(provider.hash().is_some());
        assert!(provider.aead().is_some());
    }
}
