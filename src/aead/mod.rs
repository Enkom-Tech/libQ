//! Authenticated Encryption with Associated Data (AEAD) for libQ
//!
//! This module provides post-quantum AEAD constructions.

use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for AEAD operations
pub trait Aead {
    /// Encrypt a message
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt a message
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// AEAD key with automatic memory zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey {
    pub data: Vec<u8>,
}

/// AEAD nonce
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce {
    pub data: Vec<u8>,
}

impl AeadKey {
    /// Create a new AEAD key
    ///
    /// # Arguments
    ///
    /// * `data` - The key data (will be zeroized on drop)
    ///
    /// # Returns
    ///
    /// A new AEAD key
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the key data (use with caution)
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the key size
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Validate key size
    ///
    /// # Arguments
    ///
    /// * `expected_size` - The expected key size
    ///
    /// # Returns
    ///
    /// `Ok(())` if the key size is correct, or an error if not
    pub fn validate_size(&self, expected_size: usize) -> Result<()> {
        if self.data.len() != expected_size {
            return Err(Error::InvalidKeySize {
                expected: expected_size,
                actual: self.data.len(),
            });
        }
        Ok(())
    }
}

impl Nonce {
    /// Create a new nonce
    ///
    /// # Arguments
    ///
    /// * `data` - The nonce data
    ///
    /// # Returns
    ///
    /// A new nonce
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the nonce data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the nonce size
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Validate nonce size
    ///
    /// # Arguments
    ///
    /// * `expected_size` - The expected nonce size
    ///
    /// # Returns
    ///
    /// `Ok(())` if the nonce size is correct, or an error if not
    pub fn validate_size(&self, expected_size: usize) -> Result<()> {
        if self.data.len() != expected_size {
            return Err(Error::InvalidNonceSize {
                expected: expected_size,
                actual: self.data.len(),
            });
        }
        Ok(())
    }
}

// Implement Debug for AeadKey (but don't show the actual data)
impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("data", &"[REDACTED]")
            .field("size", &self.data.len())
            .finish()
    }
}

// Implement PartialEq and Eq for AeadKey (constant-time comparison)
impl PartialEq for AeadKey {
    fn eq(&self, other: &Self) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }

        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for AeadKey {}

/// AEAD algorithm types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-GCM (for hybrid constructions)
    AesGcm,
    /// ChaCha20-Poly1305 (for hybrid constructions)
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Get the key size for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            AeadAlgorithm::AesGcm => 32, // AES-256
            AeadAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size for this algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            AeadAlgorithm::AesGcm => 12,
            AeadAlgorithm::ChaCha20Poly1305 => 12,
        }
    }

    /// Validate input parameters
    ///
    /// # Arguments
    ///
    /// * `key` - The encryption key
    /// * `nonce` - The nonce
    /// * `plaintext` - The plaintext to encrypt
    ///
    /// # Returns
    ///
    /// `Ok(())` if the parameters are valid, or an error if not
    pub fn validate_encrypt_params(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
    ) -> Result<()> {
        // Validate key size
        key.validate_size(self.key_size())?;

        // Validate nonce size
        nonce.validate_size(self.nonce_size())?;

        // Validate plaintext size
        if plaintext.is_empty() {
            return Err(Error::InvalidMessageSize { max: 0, actual: 0 });
        }

        // Check for maximum plaintext size (1GB to prevent DoS)
        const MAX_PLAINTEXT_SIZE: usize = 1024 * 1024 * 1024; // 1GB
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(Error::InvalidMessageSize {
                max: MAX_PLAINTEXT_SIZE,
                actual: plaintext.len(),
            });
        }

        Ok(())
    }

    /// Validate decryption parameters
    ///
    /// # Arguments
    ///
    /// * `key` - The decryption key
    /// * `nonce` - The nonce
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// `Ok(())` if the parameters are valid, or an error if not
    pub fn validate_decrypt_params(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
    ) -> Result<()> {
        // Validate key size
        key.validate_size(self.key_size())?;

        // Validate nonce size
        nonce.validate_size(self.nonce_size())?;

        // Validate ciphertext size (must be at least tag size)
        const MIN_CIPHERTEXT_SIZE: usize = 16; // Minimum tag size
        if ciphertext.len() < MIN_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextSize {
                expected: MIN_CIPHERTEXT_SIZE,
                actual: ciphertext.len(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_key_creation() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let key = AeadKey::new(data.clone());

        assert_eq!(key.data(), &data);
        assert_eq!(key.size(), 8);
    }

    #[test]
    fn test_nonce_creation() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = Nonce::new(data.clone());

        assert_eq!(nonce.data(), &data);
        assert_eq!(nonce.size(), 12);
    }

    #[test]
    fn test_key_size_validation() {
        let key = AeadKey::new(vec![0u8; 32]);

        assert!(key.validate_size(32).is_ok());
        assert!(key.validate_size(16).is_err());
    }

    #[test]
    fn test_nonce_size_validation() {
        let nonce = Nonce::new(vec![0u8; 12]);

        assert!(nonce.validate_size(12).is_ok());
        assert!(nonce.validate_size(16).is_err());
    }

    #[test]
    fn test_aead_algorithm_sizes() {
        assert_eq!(AeadAlgorithm::AesGcm.key_size(), 32);
        assert_eq!(AeadAlgorithm::AesGcm.nonce_size(), 12);
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_size(), 12);
    }

    #[test]
    fn test_encrypt_params_validation() {
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 12]);
        let plaintext = vec![1, 2, 3, 4];

        assert!(AeadAlgorithm::AesGcm
            .validate_encrypt_params(&key, &nonce, &plaintext)
            .is_ok());
    }

    #[test]
    fn test_decrypt_params_validation() {
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 12]);
        let ciphertext = vec![0u8; 32]; // Minimum size

        assert!(AeadAlgorithm::AesGcm
            .validate_decrypt_params(&key, &nonce, &ciphertext)
            .is_ok());
    }

    #[test]
    fn test_key_constant_time_comparison() {
        let key1 = AeadKey::new(vec![1, 2, 3, 4]);
        let key2 = AeadKey::new(vec![1, 2, 3, 4]);
        let key3 = AeadKey::new(vec![1, 2, 3, 5]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
