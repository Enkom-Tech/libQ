//! SHAKE256 AEAD Implementation
//!
//! This module provides a cryptographically secure SHAKE256-based AEAD implementation
//! using proper domain separation and authenticated encryption modes.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadKey,
    Algorithm,
    Error,
    Nonce,
    Result,
};
use lib_q_sha3::digest::{
    Update,
    XofReader,
};

// Plugin trait implementation
use crate::metadata::{
    AeadMetadata,
    AeadWithMetadata,
};
use crate::security::stack_buffer::{
    IvBuffer,
    KeyBuffer,
    StackBuffer,
    TagBuffer,
};

/// SHAKE256 AEAD implementation with proper domain separation
pub struct Shake256Aead {
    metadata: &'static AeadMetadata,
}

impl Shake256Aead {
    /// Create a new SHAKE256 AEAD instance
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::Shake256Aead)
                .expect("SHAKE256 AEAD metadata not found"),
        }
    }

    /// Domain separation constants for different operations
    const DOMAIN_ENC_KEY: &'static [u8] = b"LIBQ-SHAKE256-AEAD-ENC-KEY";
    const DOMAIN_MAC_KEY: &'static [u8] = b"LIBQ-SHAKE256-AEAD-MAC-KEY";
    const DOMAIN_IV: &'static [u8] = b"LIBQ-SHAKE256-AEAD-IV";
    const DOMAIN_TAG: &'static [u8] = b"LIBQ-SHAKE256-AEAD-TAG";

    /// Derive encryption key using domain separation
    fn derive_encryption_key(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<KeyBuffer> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_ENC_KEY);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut enc_key = KeyBuffer::new();
        enc_key.resize(32).map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: 0,
        })?;
        let mut reader = hasher.finalize_xof();
        reader.read(enc_key.as_mut_slice());
        Ok(enc_key)
    }

    /// Derive MAC key using domain separation
    fn derive_mac_key(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<KeyBuffer> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_MAC_KEY);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut mac_key = KeyBuffer::new();
        mac_key.resize(32).map_err(|_| Error::InvalidKeySize {
            expected: 32,
            actual: 0,
        })?;
        let mut reader = hasher.finalize_xof();
        reader.read(mac_key.as_mut_slice());
        Ok(mac_key)
    }

    /// Generate initialization vector using domain separation
    fn generate_iv(&self, key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<IvBuffer> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_IV);
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());

        let mut iv = IvBuffer::new();
        iv.resize(16).map_err(|_| Error::InvalidNonceSize {
            expected: 16,
            actual: 0,
        })?;
        let mut reader = hasher.finalize_xof();
        reader.read(iv.as_mut_slice());
        Ok(iv)
    }

    /// Generate authentication tag using domain separation
    fn generate_tag(
        &self,
        mac_key: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<TagBuffer> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        let mut hasher = Shake256::default();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(mac_key);
        hasher.update(associated_data);
        hasher.update(&(associated_data.len() as u64).to_le_bytes());
        hasher.update(ciphertext);
        hasher.update(&(ciphertext.len() as u64).to_le_bytes());

        let mut tag = TagBuffer::new();
        tag.resize(self.tag_size())
            .map_err(|_| Error::InvalidMessageSize { max: 0, actual: 0 })?;
        let mut reader = hasher.finalize_xof();
        reader.read(tag.as_mut_slice());
        Ok(tag)
    }

    /// Encrypt using CTR mode with SHAKE256
    fn ctr_encrypt(&self, enc_key: &[u8], iv: &[u8], plaintext: &mut [u8]) -> Result<()> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::ExtendableOutput;

        // Generate keystream using SHAKE256
        let mut hasher = Shake256::default();
        hasher.update(enc_key);
        hasher.update(iv);
        hasher.update(&(plaintext.len() as u64).to_le_bytes());

        // Use stack buffer for keystream if it fits, otherwise fall back to Vec
        if plaintext.len() <= 4096 {
            let mut keystream = StackBuffer::<4096>::new();
            keystream
                .resize(plaintext.len())
                .map_err(|_| Error::InvalidMessageSize { max: 0, actual: 0 })?;
            let mut reader = hasher.finalize_xof();
            reader.read(keystream.as_mut_slice());

            // XOR with keystream
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= keystream.as_slice()[i];
            }
        } else {
            // Fall back to Vec for larger plaintexts
            let mut keystream = vec![0u8; plaintext.len()];
            let mut reader = hasher.finalize_xof();
            reader.read(&mut keystream);

            // XOR with keystream
            for (i, byte) in plaintext.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
        }

        Ok(())
    }

    /// Decrypt using CTR mode with SHAKE256
    fn ctr_decrypt(&self, enc_key: &[u8], iv: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        // CTR decryption is the same as encryption
        self.ctr_encrypt(enc_key, iv, ciphertext)
    }

    /// Validate key material
    fn validate_key(&self, key: &AeadKey) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_key(self, key)
    }

    /// Validate nonce
    fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_nonce(self, nonce)
    }

    /// Validate ciphertext size
    fn validate_ciphertext_size(&self, size: usize) -> Result<()> {
        // Use standard validation from AeadWithMetadata trait
        AeadWithMetadata::validate_ciphertext_size(self, size)
    }

    /// Internal encrypt implementation
    fn encrypt_internal(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate inputs using security modules
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        crate::security::validation::validate_plaintext(plaintext)?;
        crate::security::validation::validate_key(key.as_bytes())?;
        crate::security::validation::validate_nonce(nonce.as_bytes())?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        // Use SHAKE256 for encryption with proper domain separation
        #[cfg(feature = "shake256")]
        {
            // Derive keys using domain separation
            let enc_key =
                self.derive_encryption_key(key.as_bytes(), nonce.as_bytes(), associated_data)?;
            let mac_key = self.derive_mac_key(key.as_bytes(), nonce.as_bytes(), associated_data)?;
            let iv = self.generate_iv(key.as_bytes(), nonce.as_bytes(), associated_data)?;

            // Encrypt plaintext
            let mut ciphertext = plaintext.to_vec();
            self.ctr_encrypt(enc_key.as_slice(), iv.as_slice(), &mut ciphertext)?;

            // Generate authentication tag
            let tag = self.generate_tag(mac_key.as_slice(), associated_data, &ciphertext)?;

            // Append tag to ciphertext
            ciphertext.extend_from_slice(tag.as_slice());

            // Secure memory cleanup is automatic with stack buffers
            Ok(ciphertext)
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation requires 'shake256' feature",
            })
        }
    }

    /// Internal decrypt implementation with constant-time execution
    fn decrypt_internal(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate inputs using security modules
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;
        crate::security::validation::validate_ciphertext(ciphertext)?;
        crate::security::validation::validate_key(key.as_bytes())?;
        crate::security::validation::validate_nonce(nonce.as_bytes())?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        // Use SHAKE256 for decryption with proper domain separation
        #[cfg(feature = "shake256")]
        {
            // Split ciphertext and tag
            let (ciphertext_data, tag) = ciphertext.split_at(ciphertext.len() - self.tag_size());

            // Derive keys using domain separation
            let enc_key =
                self.derive_encryption_key(key.as_bytes(), nonce.as_bytes(), associated_data)?;
            let mac_key = self.derive_mac_key(key.as_bytes(), nonce.as_bytes(), associated_data)?;
            let iv = self.generate_iv(key.as_bytes(), nonce.as_bytes(), associated_data)?;

            // Verify authentication tag using constant-time comparison
            let computed_tag =
                self.generate_tag(mac_key.as_slice(), associated_data, ciphertext_data)?;
            let tag_valid =
                crate::security::constant_time::constant_time_eq(tag, computed_tag.as_slice());

            // Always perform decryption to maintain constant-time execution
            let mut plaintext = ciphertext_data.to_vec();
            self.ctr_decrypt(enc_key.as_slice(), iv.as_slice(), &mut plaintext)?;

            // Return result based on tag verification, but only after all work is done
            if tag_valid {
                Ok(plaintext)
            } else {
                // Secure memory cleanup on failure is automatic with stack buffers
                Err(Error::AuthenticationFailed {
                    operation: "Tag verification failed".to_string(),
                })
            }
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(Error::NotImplemented {
                feature: "SHAKE256 AEAD implementation requires 'shake256' feature",
            })
        }
    }
}

impl Aead for Shake256Aead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Wrap the entire encrypt operation with timing protection
        crate::security::timing::protect_timing(|| {
            self.encrypt_internal(key, nonce, plaintext, associated_data)
        })
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Wrap the entire decrypt operation with timing protection
        crate::security::timing::protect_timing(|| {
            self.decrypt_internal(key, nonce, ciphertext, associated_data)
        })
    }
}

impl AeadWithMetadata for Shake256Aead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for Shake256Aead {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the plugin trait using the macro
impl crate::plugin::AeadPlugin for Shake256Aead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Shake256Aead
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::Shake256Aead)
            .expect("Metadata not found for algorithm")
    }

    fn name(&self) -> &'static str {
        "SHAKE256 AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "SHAKE256-based AEAD construction using post-quantum hash function with proper domain separation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a proper test key with good entropy
    fn create_test_key() -> AeadKey {
        AeadKey::new(vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ])
    }

    /// Generate a proper test nonce with good entropy
    fn create_test_nonce() -> Nonce {
        Nonce::new(vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ])
    }

    /// Generate a different test key for wrong key tests
    fn create_test_key2() -> AeadKey {
        AeadKey::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ])
    }

    /// Generate a different test nonce for wrong nonce tests
    fn create_test_nonce2() -> Nonce {
        Nonce::new(vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ])
    }

    #[test]
    fn test_shake256_creation() {
        let aead = Shake256Aead::new();
        assert_eq!(aead.algorithm(), Algorithm::Shake256Aead);
        assert_eq!(aead.key_size(), 32);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 32);
        assert_eq!(aead.security_level(), 1);
    }

    #[test]
    fn test_shake256_metadata() {
        let aead = Shake256Aead::new();
        let metadata = aead.metadata();

        assert_eq!(metadata.algorithm, Algorithm::Shake256Aead);
        assert_eq!(metadata.name, "SHAKE256-AEAD");
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 1);
    }

    #[test]
    fn test_shake256_validation() {
        let aead = Shake256Aead::new();

        // Test valid key
        let key = AeadKey::new(vec![0u8; 32]);
        assert!(aead.validate_key(&key).is_ok());

        // Test invalid key size
        let invalid_key = AeadKey::new(vec![0u8; 16]);
        assert!(aead.validate_key(&invalid_key).is_err());

        // Test valid nonce
        let nonce = Nonce::new(vec![0u8; 16]);
        assert!(aead.validate_nonce(&nonce).is_ok());

        // Test invalid nonce size
        let invalid_nonce = Nonce::new(vec![0u8; 12]);
        assert!(aead.validate_nonce(&invalid_nonce).is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_encrypt_decrypt() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";
        let associated_data = b"metadata";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(associated_data.as_slice()));
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        // Decrypt
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, Some(associated_data.as_slice()));
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_authentication_failure() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        // Decrypt should fail
        let result = aead.decrypt(&key, &nonce, &tampered, None);
        assert!(result.is_err());

        if let Err(Error::AuthenticationFailed { operation }) = result {
            assert!(operation.contains("Tag verification failed"));
        } else {
            panic!("Expected AuthenticationFailed error");
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_wrong_key() {
        let aead = Shake256Aead::new();

        let key1 = create_test_key();
        let key2 = create_test_key2();
        let nonce = create_test_nonce();
        let plaintext = b"Hello, World!";

        // Encrypt with key1
        let ciphertext = aead.encrypt(&key1, &nonce, plaintext, None).unwrap();

        // Decrypt with key2 should fail
        let result = aead.decrypt(&key2, &nonce, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_wrong_nonce() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce1 = create_test_nonce();
        let nonce2 = create_test_nonce2();
        let plaintext = b"Hello, World!";

        // Encrypt with nonce1
        let ciphertext = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();

        // Decrypt with nonce2 should fail
        let result = aead.decrypt(&key, &nonce2, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_empty_plaintext() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"";

        // Encrypt empty plaintext
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None);
        assert!(ciphertext.is_ok());

        let ciphertext = ciphertext.unwrap();
        assert_eq!(ciphertext.len(), aead.tag_size());

        // Decrypt should work
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_domain_separation() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let nonce = create_test_nonce();
        let plaintext = b"Test message";

        // Encrypt with different associated data should produce different ciphertexts
        let ciphertext1 = aead.encrypt(&key, &nonce, plaintext, Some(b"ad1")).unwrap();
        let ciphertext2 = aead.encrypt(&key, &nonce, plaintext, Some(b"ad2")).unwrap();

        // Should be different due to domain separation
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly with their respective AD
        let decrypted1 = aead
            .decrypt(&key, &nonce, &ciphertext1, Some(b"ad1"))
            .unwrap();
        let decrypted2 = aead
            .decrypt(&key, &nonce, &ciphertext2, Some(b"ad2"))
            .unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_nonce_uniqueness() {
        let aead = Shake256Aead::new();

        let key = create_test_key();
        let plaintext = b"Test message";

        // Encrypt with different nonces should produce different ciphertexts
        let nonce1 = create_test_nonce();
        let nonce2 = create_test_nonce2();

        let ciphertext1 = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();
        let ciphertext2 = aead.encrypt(&key, &nonce2, plaintext, None).unwrap();

        // Should be different due to nonce uniqueness
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly with their respective nonces
        let decrypted1 = aead.decrypt(&key, &nonce1, &ciphertext1, None).unwrap();
        let decrypted2 = aead.decrypt(&key, &nonce2, &ciphertext2, None).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
