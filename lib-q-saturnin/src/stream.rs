//! Saturnin stream cipher implementation
//!
//! This module provides a stream cipher mode using the Saturnin block cipher in CTR mode.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::SaturninStream;
//!
//! // Create stream cipher instance
//! let stream = SaturninStream::new();
//!
//! // Generate key and nonce (in practice, use secure random generation)
//! let key = vec![0u8; 32]; // 256-bit key
//! let nonce = vec![0u8; 16]; // 128-bit nonce
//!
//! let plaintext = b"Hello, World!";
//!
//! // Encrypt arbitrary-length data
//! let ciphertext = stream.encrypt(&key, &nonce, plaintext).unwrap();
//! assert_eq!(ciphertext.len(), plaintext.len());
//!
//! // Decrypt
//! let decrypted = stream.decrypt(&key, &nonce, &ciphertext).unwrap();
//! assert_eq!(decrypted, plaintext);
//!
//! // Generate keystream for custom use
//! let keystream = stream.generate_keystream(&key, &nonce, 100).unwrap();
//! assert_eq!(keystream.len(), 100);
//! ```
//!
//! ## Performance Notes
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 128 bits (16 bytes)
//! - **Throughput**: ~100-400 MB/s on modern hardware
//! - **Memory usage**: Constant, independent of data size
//! - **Security level**: 256-bit post-quantum security

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use lib_q_core::{
    Error,
    Result,
};

use crate::core::SaturninCore;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
use crate::simd::{
    encrypt_blocks8_dispatch,
    simd_xor,
};

/// Saturnin stream cipher implementation
///
/// Provides a stream cipher using the Saturnin block cipher in CTR (Counter) mode.
/// This allows encryption/decryption of arbitrary-length data.
pub struct SaturninStream {
    core: SaturninCore,
}

impl SaturninStream {
    /// Create a new Saturnin stream cipher instance
    pub fn new() -> Self {
        // Use 10 super-rounds and domain 1 for the stream cipher
        let core = SaturninCore::new(10, 1).expect("Valid parameters");
        Self { core }
    }

    /// Get the key size in bytes (256 bits = 32 bytes)
    pub const fn key_size() -> usize {
        32
    }

    /// Get the nonce size in bytes (128 bits = 16 bytes)
    pub const fn nonce_size() -> usize {
        16
    }

    /// Encrypt data using CTR mode
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 16-byte nonce
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Encrypted data
    pub fn encrypt(&self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ctr_mode(key, nonce, plaintext)
    }

    /// Decrypt data using CTR mode
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `nonce` - 16-byte nonce
    /// * `ciphertext` - Data to decrypt
    ///
    /// # Returns
    /// Decrypted data
    pub fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        // CTR mode is symmetric - encryption and decryption are the same
        self.ctr_mode(key, nonce, ciphertext)
    }

    /// CTR mode implementation
    ///
    /// # Arguments
    /// * `key` - 32-byte key
    /// * `nonce` - 16-byte nonce
    /// * `data` - Data to process
    ///
    /// # Returns
    /// Processed data
    fn ctr_mode(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }

        let key_len = key.len();
        let key32: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: Self::key_size(),
            actual: key_len,
        })?;

        let mut result = Vec::with_capacity(data.len());
        let mut counter = 0u32;
        let mut offset = 0;

        while offset < data.len() {
            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            if data.len() - offset >= 32 * 8 {
                let mut keystream_blocks = [[0u8; 32]; 8];
                for (lane, block) in keystream_blocks.iter_mut().enumerate() {
                    let c = counter.wrapping_add(lane as u32);
                    block[0..16].copy_from_slice(nonce);
                    block[16] = 0x80;
                    block[28..32].copy_from_slice(&c.to_be_bytes());
                }

                encrypt_blocks8_dispatch(10, 1, key, &mut keystream_blocks, Some(&self.core))?;

                for (lane, ks) in keystream_blocks.iter().enumerate() {
                    let start = offset + (lane * 32);
                    let mut in_block = [0u8; 32];
                    in_block.copy_from_slice(&data[start..start + 32]);
                    let mut out_block = [0u8; 32];
                    simd_xor::xor_blocks_32(&in_block, ks, &mut out_block);
                    result.extend_from_slice(&out_block);
                }

                offset += 32 * 8;
                let (next_counter, overflowed) = counter.overflowing_add(8);
                if overflowed {
                    return Err(Error::InvalidMessageSize {
                        max: usize::MAX,
                        actual: data.len(),
                    });
                }
                counter = next_counter;
                continue;
            }

            // Create counter block
            let mut counter_block = [0u8; 32];
            counter_block[0..16].copy_from_slice(nonce);
            counter_block[16] = 0x80; // Padding
            counter_block[28..32].copy_from_slice(&counter.to_be_bytes());

            // Encrypt counter block
            self.core.encrypt_block_32(key32, &mut counter_block)?;

            let remaining = data.len() - offset;
            let block_size = if remaining >= 32 { 32 } else { remaining };

            if block_size == 32 {
                #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
                {
                    let mut in_block = [0u8; 32];
                    in_block.copy_from_slice(&data[offset..offset + 32]);
                    let mut out_block = [0u8; 32];
                    simd_xor::xor_blocks_32(&in_block, &counter_block, &mut out_block);
                    result.extend_from_slice(&out_block);
                }

                #[cfg(not(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon")))]
                {
                    for i in 0..32 {
                        result.push(data[offset + i] ^ counter_block[i]);
                    }
                }
            } else {
                for i in 0..block_size {
                    result.push(data[offset + i] ^ counter_block[i]);
                }
            }

            offset += block_size;
            counter += 1;

            // Prevent counter overflow (safety check)
            if counter == 0 {
                return Err(Error::InvalidMessageSize {
                    max: usize::MAX,
                    actual: data.len(),
                });
            }
        }

        Ok(result)
    }

    /// Generate keystream for a given key and nonce
    ///
    /// # Arguments
    /// * `key` - 32-byte key
    /// * `nonce` - 16-byte nonce
    /// * `length` - Length of keystream to generate
    ///
    /// # Returns
    /// Generated keystream
    pub fn generate_keystream(&self, key: &[u8], nonce: &[u8], length: usize) -> Result<Vec<u8>> {
        if key.len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.len(),
            });
        }

        if nonce.len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.len(),
            });
        }

        let key_len = key.len();
        let key32: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeySize {
            expected: Self::key_size(),
            actual: key_len,
        })?;

        let mut keystream = Vec::with_capacity(length);
        let mut counter = 0u32;
        let mut generated = 0;

        while generated < length {
            #[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
            if length - generated >= 32 * 8 {
                let mut keystream_blocks = [[0u8; 32]; 8];
                for (lane, block) in keystream_blocks.iter_mut().enumerate() {
                    let c = counter.wrapping_add(lane as u32);
                    block[0..16].copy_from_slice(nonce);
                    block[16] = 0x80;
                    block[28..32].copy_from_slice(&c.to_be_bytes());
                }

                encrypt_blocks8_dispatch(10, 1, key, &mut keystream_blocks, Some(&self.core))?;

                for ks in &keystream_blocks {
                    keystream.extend_from_slice(ks);
                }
                generated += 32 * 8;
                let (next_counter, overflowed) = counter.overflowing_add(8);
                if overflowed {
                    return Err(Error::InvalidMessageSize {
                        max: usize::MAX,
                        actual: length,
                    });
                }
                counter = next_counter;
                continue;
            }

            // Create counter block
            let mut counter_block = [0u8; 32];
            counter_block[0..16].copy_from_slice(nonce);
            counter_block[16] = 0x80; // Padding
            counter_block[28..32].copy_from_slice(&counter.to_be_bytes());

            // Encrypt counter block
            self.core.encrypt_block_32(key32, &mut counter_block)?;

            // Add to keystream
            let remaining = length - generated;
            let block_size = if remaining >= 32 { 32 } else { remaining };

            keystream.extend_from_slice(&counter_block[0..block_size]);
            generated += block_size;
            counter += 1;

            // Prevent counter overflow (safety check)
            if counter == 0 {
                return Err(Error::InvalidMessageSize {
                    max: usize::MAX,
                    actual: length,
                });
            }
        }

        Ok(keystream)
    }
}

impl Default for SaturninStream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_stream_cipher_creation() {
        let _stream = SaturninStream::new();
        assert_eq!(SaturninStream::key_size(), 32);
        assert_eq!(SaturninStream::nonce_size(), 16);
    }

    #[test]
    fn test_stream_cipher_round_trip() -> Result<()> {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_stream_cipher_different_lengths() -> Result<()> {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];

        let data_100 = vec![0u8; 100];
        let data_1000 = vec![0u8; 1000];
        let test_cases = vec![
            b"".as_slice(),
            b"a".as_slice(),
            b"Hello".as_slice(),
            b"Hello, World!".as_slice(),
            &data_100,
            &data_1000,
        ];

        for plaintext in test_cases {
            let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
            let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
            assert_eq!(decrypted, plaintext);
        }

        Ok(())
    }

    #[test]
    fn test_stream_cipher_different_nonces() -> Result<()> {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce1 = vec![0u8; 16];
        let nonce2 = vec![1u8; 16];
        let plaintext = b"test message";

        let ciphertext1 = stream.encrypt(&key, &nonce1, plaintext)?;
        let ciphertext2 = stream.encrypt(&key, &nonce2, plaintext)?;

        assert_ne!(ciphertext1, ciphertext2);

        Ok(())
    }

    #[test]
    fn test_stream_cipher_different_keys() -> Result<()> {
        let stream = SaturninStream::new();
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32];
        let nonce = vec![0u8; 16];
        let plaintext = b"test message";

        let ciphertext1 = stream.encrypt(&key1, &nonce, plaintext)?;
        let ciphertext2 = stream.encrypt(&key2, &nonce, plaintext)?;

        assert_ne!(ciphertext1, ciphertext2);

        Ok(())
    }

    #[test]
    fn test_stream_cipher_invalid_key_size() {
        let stream = SaturninStream::new();
        let key = vec![0u8; 16]; // Wrong size
        let nonce = vec![0u8; 16];
        let plaintext = b"test";

        let result = stream.encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_cipher_invalid_nonce_size() {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 8]; // Wrong size
        let plaintext = b"test";

        let result = stream.encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_keystream_generation() -> Result<()> {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];

        let keystream = stream.generate_keystream(&key, &nonce, 100)?;
        assert_eq!(keystream.len(), 100);

        // Generate same keystream again
        let keystream2 = stream.generate_keystream(&key, &nonce, 100)?;
        assert_eq!(keystream, keystream2);

        Ok(())
    }

    #[test]
    fn test_keystream_different_nonces() -> Result<()> {
        let stream = SaturninStream::new();
        let key = vec![0u8; 32];
        let nonce1 = vec![0u8; 16];
        let nonce2 = vec![1u8; 16];

        let keystream1 = stream.generate_keystream(&key, &nonce1, 50)?;
        let keystream2 = stream.generate_keystream(&key, &nonce2, 50)?;

        assert_ne!(keystream1, keystream2);

        Ok(())
    }
}
