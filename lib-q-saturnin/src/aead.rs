//! Saturnin AEAD implementation
//!
//! Saturnin is a lightweight post-quantum symmetric algorithm suite designed
//! for IoT and constrained devices, providing authenticated encryption and
//! hashing modes with superior post-quantum security.
//!
//! ## Usage Example
//!
//! ```rust
//! use lib_q_saturnin::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     SaturninAead,
//! };
//!
//! // Create AEAD instance
//! let aead = SaturninAead::new();
//!
//! // Generate key and nonce (in practice, use secure random generation)
//! let key = AeadKey {
//!     data: vec![0u8; 32],
//! };
//! let nonce = Nonce {
//!     data: vec![0u8; 16],
//! };
//!
//! let plaintext = b"Secret message";
//! let associated_data = b"metadata";
//!
//! // Encrypt with associated data
//! let ciphertext = aead
//!     .encrypt(&key, &nonce, plaintext, Some(associated_data))
//!     .unwrap();
//!
//! // Decrypt and verify authenticity
//! let decrypted = aead
//!     .decrypt(&key, &nonce, &ciphertext, Some(associated_data))
//!     .unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Performance Notes
//!
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 128 bits (16 bytes)  
//! - **Tag size**: 256 bits (32 bytes)
//! - **Throughput**: ~100-500 MB/s on modern hardware
//! - **Memory usage**: Minimal, stateless design

#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};

use crate::core::SaturninCore;

/// Saturnin AEAD implementation
///
/// Provides authenticated encryption using the Saturnin CTR-Cascade mode.
/// This is the full AEAD mode that supports associated data and arbitrary
/// length plaintexts.
pub struct SaturninAead {
    // No state needed - all operations are stateless
}

impl SaturninAead {
    /// Create a new Saturnin AEAD instance
    pub fn new() -> Self {
        Self {}
    }

    /// Get the key size in bytes (256 bits = 32 bytes)
    pub const fn key_size() -> usize {
        32
    }

    /// Get the nonce size in bytes (128 bits = 16 bytes)
    pub const fn nonce_size() -> usize {
        16
    }

    /// Get the tag size in bytes (256 bits = 32 bytes)
    pub const fn tag_size() -> usize {
        32
    }

    /// Initialize the cascade state
    fn cascade_init(&self, key: &[u8], nonce: &[u8]) -> Result<[u8; 32]> {
        let mut r = [0u8; 32];

        // Copy nonce to first 16 bytes
        r[0..16].copy_from_slice(nonce);
        r[16] = 0x80;
        // Remaining bytes are already zero

        // Encrypt with cascade parameters: 10 super-rounds, domain 2 (AAD1)
        let core = SaturninCore::new(10, 2)?;
        core.encrypt_block(key, &mut r)?;

        // XOR with nonce
        for i in 0..16 {
            r[i] ^= nonce[i];
        }
        r[16] ^= 0x80;

        Ok(r)
    }

    /// Apply cascade construction to data (optimized)
    fn cascade(&self, r: &mut [u8; 32], d1: u8, d2: u8, data: &[u8]) -> Result<()> {
        // Pre-allocate cores to avoid repeated allocation overhead
        let core_d1 = SaturninCore::new(10, d1)?;
        let core_d2 = SaturninCore::new(10, d2)?;

        let mut offset = 0;

        loop {
            let mut t = [0u8; 32];
            let mut m = [0u8; 32];
            let remaining = data.len() - offset;

            if remaining >= 32 {
                t.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                // Use pre-allocated core for d1
                m.copy_from_slice(&t);
                core_d1.encrypt_block(r, &mut m)?;
            } else {
                t[0..remaining].copy_from_slice(&data[offset..]);
                t[remaining] = 0x80;
                // Remaining bytes are already zero

                // Use pre-allocated core for d2
                m.copy_from_slice(&t);
                core_d2.encrypt_block(r, &mut m)?;
            }

            // Optimized XOR operation - process 8 bytes at a time
            for chunk in (0..32).step_by(8) {
                let m_chunk = u64::from_le_bytes([
                    m[chunk],
                    m[chunk + 1],
                    m[chunk + 2],
                    m[chunk + 3],
                    m[chunk + 4],
                    m[chunk + 5],
                    m[chunk + 6],
                    m[chunk + 7],
                ]);
                let t_chunk = u64::from_le_bytes([
                    t[chunk],
                    t[chunk + 1],
                    t[chunk + 2],
                    t[chunk + 3],
                    t[chunk + 4],
                    t[chunk + 5],
                    t[chunk + 6],
                    t[chunk + 7],
                ]);

                let result = m_chunk ^ t_chunk;
                let result_bytes = result.to_le_bytes();
                r[chunk..chunk + 8].copy_from_slice(&result_bytes);
            }

            if remaining < 32 {
                break;
            }
        }

        Ok(())
    }

    /// CTR encryption/decryption (optimized)
    fn ctr_encrypt(&self, key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<()> {
        // Pre-allocate core to avoid repeated allocation overhead
        let core = SaturninCore::new(10, 1)?; // CTR uses domain 1

        let mut counter = 1u32; // Counter starts at 1
        let mut offset = 0;

        while offset < data.len() {
            let mut keystream = [0u8; 32];

            // Build counter block efficiently
            keystream[0..16].copy_from_slice(nonce);
            keystream[16] = 0x80;
            // Bytes 17-27 are zero
            keystream[28] = (counter >> 24) as u8;
            keystream[29] = (counter >> 16) as u8;
            keystream[30] = (counter >> 8) as u8;
            keystream[31] = counter as u8;

            // Encrypt to get keystream
            core.encrypt_block(key, &mut keystream)?;

            // Optimized XOR with data - process 8 bytes at a time
            let remaining = data.len() - offset;
            let block_len = remaining.min(32);

            for chunk in (0..block_len).step_by(8) {
                let chunk_end = (chunk + 8).min(block_len);
                if chunk_end - chunk == 8 {
                    // Full 8-byte chunk
                    let data_chunk = u64::from_le_bytes([
                        data[offset + chunk],
                        data[offset + chunk + 1],
                        data[offset + chunk + 2],
                        data[offset + chunk + 3],
                        data[offset + chunk + 4],
                        data[offset + chunk + 5],
                        data[offset + chunk + 6],
                        data[offset + chunk + 7],
                    ]);
                    let keystream_chunk = u64::from_le_bytes([
                        keystream[chunk],
                        keystream[chunk + 1],
                        keystream[chunk + 2],
                        keystream[chunk + 3],
                        keystream[chunk + 4],
                        keystream[chunk + 5],
                        keystream[chunk + 6],
                        keystream[chunk + 7],
                    ]);

                    let result = data_chunk ^ keystream_chunk;
                    let result_bytes = result.to_le_bytes();
                    data[offset + chunk..offset + chunk + 8].copy_from_slice(&result_bytes);
                } else {
                    // Partial chunk - fallback to byte-wise XOR
                    for i in chunk..chunk_end {
                        data[offset + i] ^= keystream[i];
                    }
                }
            }

            offset += block_len;
            counter = counter.wrapping_add(1);
        }

        Ok(())
    }
}

impl Aead for SaturninAead {
    /// Encrypt data with authentication
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `nonce` - 128-bit nonce
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Encrypted data with authentication tag appended
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.as_bytes().len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.as_bytes().len(),
            });
        }

        if nonce.as_bytes().len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }

        // Check length limits (about 137.4 GB)
        if (plaintext.len() >> 5) >= 0xFFFFFFFD {
            return Err(Error::InvalidMessageSize {
                max: 0xFFFFFFFD << 5,
                actual: plaintext.len(),
            });
        }

        let ad = associated_data.unwrap_or(&[]);

        // Initialize cascade state
        let mut tag = self.cascade_init(key.as_bytes(), nonce.as_bytes())?;

        // Process associated data
        self.cascade(&mut tag, 2, 3, ad)?;

        // Encrypt plaintext with CTR
        let mut ciphertext = plaintext.to_vec();
        self.ctr_encrypt(key.as_bytes(), nonce.as_bytes(), &mut ciphertext)?;

        // Continue cascade on ciphertext
        self.cascade(&mut tag, 4, 5, &ciphertext)?;

        // Append tag
        ciphertext.extend_from_slice(&tag);

        Ok(ciphertext)
    }

    /// Decrypt and verify data
    ///
    /// # Arguments
    /// * `key` - 256-bit decryption key
    /// * `nonce` - 128-bit nonce
    /// * `ciphertext` - Encrypted data with authentication tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.as_bytes().len() != Self::key_size() {
            return Err(Error::InvalidKeySize {
                expected: Self::key_size(),
                actual: key.as_bytes().len(),
            });
        }

        if nonce.as_bytes().len() != Self::nonce_size() {
            return Err(Error::InvalidNonceSize {
                expected: Self::nonce_size(),
                actual: nonce.as_bytes().len(),
            });
        }

        // Check length limits
        if (ciphertext.len() >> 5) >= 0xFFFFFFFE {
            return Err(Error::InvalidMessageSize {
                max: 0xFFFFFFFE << 5,
                actual: ciphertext.len(),
            });
        }

        // Check that there's enough room for the tag
        if ciphertext.len() < 32 {
            return Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            });
        }

        let ad = associated_data.unwrap_or(&[]);
        let plaintext_len = ciphertext.len() - 32;
        let ciphertext_data = &ciphertext[0..plaintext_len];
        let received_tag = &ciphertext[plaintext_len..];

        // Initialize cascade state
        let mut tag = self.cascade_init(key.as_bytes(), nonce.as_bytes())?;

        // Process associated data
        self.cascade(&mut tag, 2, 3, ad)?;

        // Continue cascade on ciphertext
        self.cascade(&mut tag, 4, 5, ciphertext_data)?;

        // Verify tag
        if tag != received_tag {
            return Err(Error::VerificationFailed {
                operation: "AEAD tag verification".to_string(),
            });
        }

        // Decrypt plaintext with CTR
        let mut plaintext = ciphertext_data.to_vec();
        self.ctr_encrypt(key.as_bytes(), nonce.as_bytes(), &mut plaintext)?;

        Ok(plaintext)
    }
}

impl Default for SaturninAead {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;

    #[test]
    fn test_saturnin_creation() {
        let _aead = SaturninAead::new();
        // Saturnin implementation created successfully
        // Test passes if we reach this point without panicking
    }

    #[test]
    fn test_saturnin_constants() {
        assert_eq!(SaturninAead::key_size(), 32);
        assert_eq!(SaturninAead::nonce_size(), 16);
        assert_eq!(SaturninAead::tag_size(), 32);
    }

    #[test]
    fn test_saturnin_encrypt_decrypt_round_trip() -> Result<()> {
        let aead = SaturninAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = b"test"; // 4 bytes
        let ad: Option<&[u8]> = None;

        // Test encryption
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, ad)?;
        assert_eq!(ciphertext.len(), plaintext.len() + 32); // plaintext + 32-byte tag

        // Test decryption
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, ad)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }
}
