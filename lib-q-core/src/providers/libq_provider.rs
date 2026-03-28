//! Main lib-Q cryptographic provider implementation
//!
//! This module provides the main LibQCryptoProvider that implements
//! the CryptoProvider trait and delegates to specific operation providers.

#[cfg(feature = "std")]
use super::{
    LibQAeadStubProvider,
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
    aead_provider: LibQAeadStubProvider,
}

// WASM-compatible version
#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct LibQCryptoProvider {
    kem_provider: WasmKemProvider,
    signature_provider: WasmSignatureProvider,
    hash_provider: WasmHashProvider,
    aead_provider: WasmAeadProvider,
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
            aead_provider: LibQAeadStubProvider::new()?,
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

    /// Get the stub AEAD provider (use `lib-q-aead` for real AEAD).
    pub fn aead_provider(&self) -> &LibQAeadStubProvider {
        &self.aead_provider
    }
}

// WASM-compatible implementation
#[cfg(not(feature = "std"))]
impl LibQCryptoProvider {
    /// Create a new lib-Q cryptographic provider (WASM version)
    pub fn new() -> Result<Self> {
        Ok(Self {
            kem_provider: WasmKemProvider::new()?,
            signature_provider: WasmSignatureProvider::new()?,
            hash_provider: WasmHashProvider::new()?,
            aead_provider: WasmAeadProvider::new()?,
        })
    }

    /// Get the KEM provider
    pub fn kem_provider(&self) -> &WasmKemProvider {
        &self.kem_provider
    }

    /// Get the signature provider
    pub fn signature_provider(&self) -> &WasmSignatureProvider {
        &self.signature_provider
    }

    /// Get the hash provider
    pub fn hash_provider(&self) -> &WasmHashProvider {
        &self.hash_provider
    }

    /// Get the AEAD provider
    pub fn aead_provider(&self) -> &WasmAeadProvider {
        &self.aead_provider
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

// WASM-specific provider implementations
#[cfg(not(feature = "std"))]
use alloc::format;

#[cfg(not(feature = "std"))]
use crate::security::SecurityValidator;
#[cfg(not(feature = "std"))]
use crate::traits::{
    AeadKey,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    Nonce,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};

#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct WasmKemProvider {
    security_validator: SecurityValidator,
}

#[cfg(not(feature = "std"))]
impl WasmKemProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(not(feature = "std"))]
impl KemOperations for WasmKemProvider {
    fn generate_keypair(
        &self,
        algorithm: crate::api::Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM KEM operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn encapsulate(
        &self,
        algorithm: crate::api::Algorithm,
        public_key: &KemPublicKey,
        randomness: Option<&[u8]>,
    ) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate public key
        self.security_validator
            .validate_public_key(algorithm, public_key.as_bytes())?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM KEM operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn decapsulate(
        &self,
        algorithm: crate::api::Algorithm,
        secret_key: &KemSecretKey,
        ciphertext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM KEM operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn derive_public_key(
        &self,
        algorithm: crate::api::Algorithm,
        secret_key: &KemSecretKey,
    ) -> Result<KemPublicKey> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Kem)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM KEM operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }
}

#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct WasmSignatureProvider {
    security_validator: SecurityValidator,
}

#[cfg(not(feature = "std"))]
impl WasmSignatureProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(not(feature = "std"))]
impl SignatureOperations for WasmSignatureProvider {
    fn generate_keypair(
        &self,
        algorithm: crate::api::Algorithm,
        randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Signature)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM Signature operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn sign(
        &self,
        algorithm: crate::api::Algorithm,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: Option<&[u8]>,
    ) -> Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Signature)?;

        // Validate secret key
        self.security_validator
            .validate_secret_key(algorithm, secret_key.as_bytes())?;

        // Validate message
        self.security_validator.validate_message(message)?;

        // Validate randomness if provided
        if let Some(rng) = randomness {
            self.security_validator.validate_randomness(rng)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM Signature operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn verify(
        &self,
        algorithm: crate::api::Algorithm,
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
        self.security_validator.validate_message(message)?;

        // Validate signature
        self.security_validator
            .validate_signature(algorithm, signature)?;

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM Signature operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }
}

#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct WasmHashProvider {
    security_validator: SecurityValidator,
}

#[cfg(not(feature = "std"))]
impl WasmHashProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(not(feature = "std"))]
impl HashOperations for WasmHashProvider {
    fn hash(&self, algorithm: crate::api::Algorithm, data: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Hash)?;

        // Validate data
        self.security_validator.validate_message(data)?;

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM Hash operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }
}

#[cfg(not(feature = "std"))]
#[derive(Clone)]
pub struct WasmAeadProvider {
    security_validator: SecurityValidator,
}

#[cfg(not(feature = "std"))]
impl WasmAeadProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }
}

#[cfg(not(feature = "std"))]
impl AeadOperations for WasmAeadProvider {
    fn encrypt(
        &self,
        algorithm: crate::api::Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Aead)?;

        // Validate key
        self.security_validator
            .validate_key_material(key.as_bytes())?;

        // Validate nonce
        self.security_validator.validate_nonce(nonce.as_bytes())?;

        // Validate plaintext
        self.security_validator.validate_message(plaintext)?;

        // Validate associated data if present
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM AEAD operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }

    fn decrypt(
        &self,
        algorithm: crate::api::Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, crate::api::AlgorithmCategory::Aead)?;

        // Validate key
        self.security_validator
            .validate_key_material(key.as_bytes())?;

        // Validate nonce
        self.security_validator.validate_nonce(nonce.as_bytes())?;

        // Validate ciphertext
        self.security_validator
            .validate_ciphertext(algorithm, ciphertext)?;

        // Validate associated data if present
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        // Return proper error indicating WASM implementation needed
        Err(crate::error::Error::NotImplemented {
            feature: format!(
                "WASM AEAD operations for {} - implementations are provided by the main lib-q crate",
                algorithm
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

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
        let provider = match LibQCryptoProvider::new() {
            Ok(p) => p,
            Err(e) => panic!("LibQCryptoProvider::new() failed: {e}"),
        };
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
        let provider = match LibQCryptoProvider::new() {
            Ok(p) => p,
            Err(e) => panic!("LibQCryptoProvider::new() failed: {e}"),
        };

        // Test that all operation providers are accessible
        assert!(provider.kem().is_some());
        assert!(provider.signature().is_some());
        assert!(provider.hash().is_some());
        assert!(provider.aead().is_some());
    }
}
