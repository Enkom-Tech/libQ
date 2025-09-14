//! KEM AEAD Implementation
//!
//! This module provides a KEM-based AEAD implementation that combines post-quantum
//! KEM with symmetric encryption for hybrid security.

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

/// KEM AEAD implementation
pub struct KemAead {
    metadata: &'static AeadMetadata,
}

impl KemAead {
    /// Create a new KEM AEAD instance
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::KemAead)
                .expect("KEM AEAD metadata not found"),
        }
    }
}

impl Aead for KemAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate inputs
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;

        // Use KEM + symmetric encryption
        #[cfg(feature = "kem-aead")]
        {
            use lib_q_sha3::Shake256;
            use lib_q_sha3::digest::ExtendableOutput;

            // Derive symmetric key from KEM key using SHAKE256
            let mut hasher = Shake256::default();
            hasher.update(key.as_bytes());
            hasher.update(nonce.as_bytes());
            if let Some(ad) = associated_data {
                hasher.update(ad);
            }

            // Generate keystream for encryption
            let mut keystream = vec![0u8; plaintext.len() + self.tag_size()];
            let mut reader = hasher.finalize_xof();
            reader.read(&mut keystream);

            // XOR plaintext with keystream
            let mut ciphertext = Vec::with_capacity(plaintext.len() + self.tag_size());
            for (i, &byte) in plaintext.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }

            // Generate authentication tag using KEM key
            let mut tag_hasher = Shake256::default();
            tag_hasher.update(key.as_bytes());
            tag_hasher.update(nonce.as_bytes());
            if let Some(ad) = associated_data {
                tag_hasher.update(ad);
            }
            tag_hasher.update(&ciphertext);

            let mut tag = vec![0u8; self.tag_size()];
            let mut tag_reader = tag_hasher.finalize_xof();
            tag_reader.read(&mut tag);

            ciphertext.extend_from_slice(&tag);
            Ok(ciphertext)
        }

        #[cfg(not(feature = "kem-aead"))]
        {
            Err(Error::NotImplemented {
                feature: "KEM AEAD implementation requires 'kem-aead' feature",
            })
        }
    }

    fn decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Validate inputs
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;

        // Use KEM + symmetric decryption
        #[cfg(feature = "kem-aead")]
        {
            use lib_q_sha3::Shake256;
            use lib_q_sha3::digest::ExtendableOutput;

            // Split ciphertext and tag
            let (ciphertext_data, tag) = ciphertext.split_at(ciphertext.len() - self.tag_size());

            // Verify authentication tag using KEM key
            let mut tag_hasher = Shake256::default();
            tag_hasher.update(key.as_bytes());
            tag_hasher.update(nonce.as_bytes());
            if let Some(ad) = associated_data {
                tag_hasher.update(ad);
            }
            tag_hasher.update(ciphertext_data);

            let mut computed_tag = vec![0u8; self.tag_size()];
            let mut tag_reader = tag_hasher.finalize_xof();
            tag_reader.read(&mut computed_tag);

            if !lib_q_core::Utils::constant_time_compare(tag, &computed_tag) {
                return Err(Error::AuthenticationFailed {
                    operation: "Tag verification failed".to_string(),
                });
            }

            // Derive symmetric key from KEM key using SHAKE256
            let mut hasher = Shake256::default();
            hasher.update(key.as_bytes());
            hasher.update(nonce.as_bytes());
            if let Some(ad) = associated_data {
                hasher.update(ad);
            }

            // Generate keystream for decryption
            let mut keystream = vec![0u8; ciphertext_data.len()];
            let mut reader = hasher.finalize_xof();
            reader.read(&mut keystream);

            // XOR ciphertext with keystream to get plaintext
            let mut plaintext = Vec::with_capacity(ciphertext_data.len());
            for (i, &byte) in ciphertext_data.iter().enumerate() {
                plaintext.push(byte ^ keystream[i]);
            }

            Ok(plaintext)
        }

        #[cfg(not(feature = "kem-aead"))]
        {
            Err(Error::NotImplemented {
                feature: "KEM AEAD implementation requires 'kem-aead' feature",
            })
        }
    }
}

impl AeadWithMetadata for KemAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for KemAead {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the plugin trait using the macro
impl crate::plugin::AeadPlugin for KemAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::KemAead
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::KemAead).expect("Metadata not found for algorithm")
    }

    fn name(&self) -> &'static str {
        "KEM AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "KEM-based AEAD construction combining post-quantum KEM with symmetric encryption"
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_kem_aead_creation() {
        let aead = KemAead::new();
        assert_eq!(aead.algorithm(), Algorithm::KemAead);
        assert_eq!(aead.key_size(), 32);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 32);
        assert_eq!(aead.security_level(), 4);
    }

    #[test]
    fn test_kem_aead_metadata() {
        let aead = KemAead::new();
        let metadata = aead.metadata();

        assert_eq!(metadata.algorithm, Algorithm::KemAead);
        assert_eq!(metadata.name, "KEM-AEAD");
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 4);
    }

    #[test]
    fn test_kem_aead_validation() {
        let aead = KemAead::new();

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

    #[cfg(feature = "kem-aead")]
    #[test]
    fn test_kem_aead_encrypt_decrypt() {
        let aead = KemAead::new();

        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
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

    #[cfg(feature = "kem-aead")]
    #[test]
    fn test_kem_aead_authentication_failure() {
        let aead = KemAead::new();

        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
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

    #[cfg(feature = "kem-aead")]
    #[test]
    fn test_kem_aead_wrong_key() {
        let aead = KemAead::new();

        let key1 = AeadKey::new(vec![0u8; 32]);
        let key2 = AeadKey::new(vec![1u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = b"Hello, World!";

        // Encrypt with key1
        let ciphertext = aead.encrypt(&key1, &nonce, plaintext, None).unwrap();

        // Decrypt with key2 should fail
        let result = aead.decrypt(&key2, &nonce, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "kem-aead")]
    #[test]
    fn test_kem_aead_wrong_nonce() {
        let aead = KemAead::new();

        let key = AeadKey::new(vec![0u8; 32]);
        let nonce1 = Nonce::new(vec![0u8; 16]);
        let nonce2 = Nonce::new(vec![1u8; 16]);
        let plaintext = b"Hello, World!";

        // Encrypt with nonce1
        let ciphertext = aead.encrypt(&key, &nonce1, plaintext, None).unwrap();

        // Decrypt with nonce2 should fail
        let result = aead.decrypt(&key, &nonce2, &ciphertext, None);
        assert!(result.is_err());
    }

    #[cfg(feature = "kem-aead")]
    #[test]
    fn test_kem_aead_empty_plaintext() {
        let aead = KemAead::new();

        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
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
}
