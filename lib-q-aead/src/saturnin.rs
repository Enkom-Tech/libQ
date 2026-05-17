//! Saturnin AEAD Implementation
//!
//! This module provides the Saturnin AEAD implementation using the lib-q-saturnin crate.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    Algorithm,
    DecryptSemanticOutcome,
    Nonce,
    Result,
};

// Plugin trait implementation
use crate::metadata::{
    AeadMetadata,
    AeadWithMetadata,
};

/// Saturnin AEAD implementation wrapper
pub struct SaturninAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_saturnin::SaturninAead,
}

impl SaturninAead {
    /// Create a new Saturnin AEAD instance
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::Saturnin)
                .expect("Saturnin metadata not found"),
            inner: lib_q_saturnin::SaturninAead::new(),
        }
    }
}

impl Aead for SaturninAead {
    fn encrypt(
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

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        // Use lib-q-saturnin for encryption.
        #[cfg(feature = "saturnin")]
        {
            self.inner
                .encrypt(key, nonce, plaintext, Some(associated_data))
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Saturnin AEAD implementation requires 'saturnin' feature",
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
        // Validate inputs using security modules
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;
        crate::security::validation::validate_ciphertext(ciphertext)?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        // Use lib-q-saturnin for decryption.
        #[cfg(feature = "saturnin")]
        {
            self.inner
                .decrypt(key, nonce, ciphertext, Some(associated_data))
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Saturnin AEAD implementation requires 'saturnin' feature",
            })
        }
    }
}

impl AeadDecryptSemantic for SaturninAead {
    fn decrypt_semantic(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<DecryptSemanticOutcome> {
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;
        crate::security::validation::validate_ciphertext(ciphertext)?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        #[cfg(feature = "saturnin")]
        {
            self.inner
                .decrypt_semantic(key, nonce, ciphertext, Some(associated_data))
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Saturnin AEAD implementation requires 'saturnin' feature",
            })
        }
    }
}

impl AeadWithMetadata for SaturninAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for SaturninAead {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the plugin trait using the macro
impl crate::plugin::AeadPlugin for SaturninAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Saturnin
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::Saturnin)
            .expect("Metadata not found for algorithm")
    }

    fn name(&self) -> &'static str {
        "Saturnin AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "Lightweight post-quantum symmetric algorithm suite for IoT and constrained devices"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saturnin_creation() {
        let aead = SaturninAead::new();
        assert_eq!(aead.algorithm(), Algorithm::Saturnin);
        assert_eq!(aead.key_size(), 32);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 32);
        assert_eq!(aead.security_level(), 1);
    }

    #[test]
    fn test_saturnin_metadata() {
        let aead = SaturninAead::new();
        let metadata = aead.metadata();

        assert_eq!(metadata.algorithm, Algorithm::Saturnin);
        assert_eq!(metadata.name, "Saturnin");
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 1);
    }

    #[test]
    fn test_saturnin_validation() {
        let aead = SaturninAead::new();

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

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_encrypt_decrypt() {
        let aead = SaturninAead::new();

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

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_authentication_failure() {
        let aead = SaturninAead::new();

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

        if let Err(lib_q_core::Error::VerificationFailed { operation }) = result {
            assert!(operation.contains("AEAD tag verification"));
        } else {
            panic!("Expected VerificationFailed error");
        }
    }

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_wrong_key() {
        let aead = SaturninAead::new();

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

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_wrong_nonce() {
        let aead = SaturninAead::new();

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
}
