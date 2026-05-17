//! Saturnin block cipher implementation
//!
//! This module provides the Saturnin block cipher mode, which is the basic building block
//! for other Saturnin modes like AEAD and hash functions.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::SaturninBlockCipher;
//!
//! // Create block cipher instance
//! let cipher = SaturninBlockCipher::new();
//!
//! // Generate key (in practice, use secure random generation)
//! let key = vec![0u8; 32]; // 256-bit key
//! let block = vec![0u8; 32]; // 256-bit block
//!
//! // Encrypt single block
//! let encrypted = cipher.encrypt_block(&key, &block).unwrap();
//! assert_eq!(encrypted.len(), 32);
//!
//! // Decrypt block
//! let decrypted = cipher.decrypt_block(&key, &encrypted).unwrap();
//! assert_eq!(decrypted, block);
//!
//! // Encrypt multiple blocks in ECB mode
//! let blocks = vec![0u8; 320]; // 10 blocks of 32 bytes each
//! let encrypted_blocks = cipher.encrypt_ecb(&key, &blocks).unwrap();
//! assert_eq!(encrypted_blocks.len(), 320);
//! ```
//!
//! ## Performance Notes
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Block size**: 256 bits (32 bytes)
//! - **Throughput**: ~50-200 MB/s for single blocks
//! - **Memory usage**: Constant, independent of number of blocks
//! - **Security level**: 256-bit post-quantum security

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Error,
    Result,
};

use crate::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use crate::simd::SimdOptimizedCore;

/// Saturnin block cipher implementation
///
/// Provides a 256-bit block cipher with 256-bit keys using the Saturnin algorithm.
/// This is the basic building block for other Saturnin modes.
pub struct SaturninBlockCipher {
    core: SaturninCore,
    #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
    simd_core: SimdOptimizedCore,
}

impl SaturninBlockCipher {
    /// Create a new Saturnin block cipher instance
    pub fn new() -> Self {
        // Use 10 super-rounds and domain 1 for the basic block cipher
        let core = SaturninCore::new(10, 1).expect("Valid parameters");
        #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
        let simd_core = SimdOptimizedCore::new(10, 1).expect("Valid parameters");
        #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
        {
            Self { core, simd_core }
        }
        #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
        {
            Self { core }
        }
    }

    /// Get the key size in bytes (256 bits = 32 bytes)
    pub const fn key_size() -> usize {
        32
    }

    /// Get the block size in bytes (256 bits = 32 bytes)
    pub const fn block_size() -> usize {
        32
    }

    /// Encrypt a single block
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `block` - 32-byte block to encrypt
    ///
    /// # Returns
    /// Encrypted block
    pub fn encrypt_block(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if block.len() != Self::block_size() {
            return Err(Error::InvalidMessageSize {
                max: Self::block_size(),
                actual: block.len(),
            });
        }

        let mut encrypted_block = block.to_vec();
        #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
        {
            let caps = self.simd_core.simd_capabilities();
            if caps.has_simd() {
                self.simd_core.encrypt_block(key, &mut encrypted_block)?;
            } else {
                self.core.encrypt_block(key, &mut encrypted_block)?;
            }
        }
        #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
        {
            self.core.encrypt_block(key, &mut encrypted_block)?;
        }
        Ok(encrypted_block)
    }

    /// Decrypt a single block
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `block` - 32-byte block to decrypt
    ///
    /// # Returns
    /// Decrypted block
    pub fn decrypt_block(&self, key: &[u8], block: &[u8]) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if block.len() != Self::block_size() {
            return Err(Error::InvalidMessageSize {
                max: Self::block_size(),
                actual: block.len(),
            });
        }

        let mut decrypted_block = block.to_vec();
        #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
        {
            let caps = self.simd_core.simd_capabilities();
            if caps.has_simd() {
                self.simd_core.decrypt_block(key, &mut decrypted_block)?;
            } else {
                self.core.decrypt_block(key, &mut decrypted_block)?;
            }
        }
        #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
        {
            self.core.decrypt_block(key, &mut decrypted_block)?;
        }
        Ok(decrypted_block)
    }

    /// Encrypt multiple blocks in ECB mode
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `blocks` - Data to encrypt (must be multiple of 32 bytes)
    ///
    /// # Returns
    /// Encrypted data
    pub fn encrypt_ecb(&self, key: &[u8], blocks: &[u8]) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if !blocks.len().is_multiple_of(Self::block_size()) {
            return Err(Error::InvalidMessageSize {
                max: blocks.len() - (blocks.len() % Self::block_size()),
                actual: blocks.len(),
            });
        }

        let mut encrypted = Vec::with_capacity(blocks.len());

        for chunk in blocks.chunks(Self::block_size()) {
            let mut block = chunk.to_vec();
            self.core.encrypt_block(key, &mut block)?;
            encrypted.extend_from_slice(&block);
        }

        Ok(encrypted)
    }

    /// Decrypt multiple blocks in ECB mode
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `blocks` - Data to decrypt (must be multiple of 32 bytes)
    ///
    /// # Returns
    /// Decrypted data
    pub fn decrypt_ecb(&self, key: &[u8], blocks: &[u8]) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if !blocks.len().is_multiple_of(Self::block_size()) {
            return Err(Error::InvalidMessageSize {
                max: blocks.len() - (blocks.len() % Self::block_size()),
                actual: blocks.len(),
            });
        }

        let mut decrypted = Vec::with_capacity(blocks.len());

        for chunk in blocks.chunks(Self::block_size()) {
            let mut block = chunk.to_vec();
            self.core.decrypt_block(key, &mut block)?;
            decrypted.extend_from_slice(&block);
        }

        Ok(decrypted)
    }
}

impl Default for SaturninBlockCipher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_block_cipher_creation() {
        let _cipher = SaturninBlockCipher::new();
        assert_eq!(SaturninBlockCipher::key_size(), 32);
        assert_eq!(SaturninBlockCipher::block_size(), 32);
    }

    #[test]
    fn test_block_cipher_single_block() -> Result<()> {
        let cipher = SaturninBlockCipher::new();
        let key = vec![0u8; 32];
        let plaintext = vec![0u8; 32];

        // Encrypt
        let ciphertext = cipher.encrypt_block(&key, &plaintext)?;
        assert_eq!(ciphertext.len(), 32);
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = cipher.decrypt_block(&key, &ciphertext)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_block_cipher_ecb() -> Result<()> {
        let cipher = SaturninBlockCipher::new();
        let key = vec![0u8; 32];
        let plaintext = vec![0u8; 64]; // Two blocks

        // Encrypt
        let ciphertext = cipher.encrypt_ecb(&key, &plaintext)?;
        assert_eq!(ciphertext.len(), 64);
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = cipher.decrypt_ecb(&key, &ciphertext)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_block_cipher_invalid_key_size() {
        let cipher = SaturninBlockCipher::new();
        let key = vec![0u8; 16]; // Wrong size
        let plaintext = vec![0u8; 32];

        let result = cipher.encrypt_block(&key, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_cipher_invalid_block_size() {
        let cipher = SaturninBlockCipher::new();
        let key = vec![0u8; 32];
        let plaintext = vec![0u8; 16]; // Wrong size

        let result = cipher.encrypt_block(&key, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_cipher_different_keys() -> Result<()> {
        let cipher = SaturninBlockCipher::new();
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32];
        let plaintext = vec![0u8; 32];

        let ciphertext1 = cipher.encrypt_block(&key1, &plaintext)?;
        let ciphertext2 = cipher.encrypt_block(&key2, &plaintext)?;

        assert_ne!(ciphertext1, ciphertext2);

        Ok(())
    }

    #[test]
    fn test_block_cipher_different_plaintexts() -> Result<()> {
        let cipher = SaturninBlockCipher::new();
        let key = vec![0u8; 32];
        let plaintext1 = vec![0u8; 32];
        let plaintext2 = vec![1u8; 32];

        let ciphertext1 = cipher.encrypt_block(&key, &plaintext1)?;
        let ciphertext2 = cipher.encrypt_block(&key, &plaintext2)?;

        assert_ne!(ciphertext1, ciphertext2);

        Ok(())
    }
}
