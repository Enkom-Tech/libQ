//! Rocca-S AEAD Implementation
//!
//! This module provides the Rocca-S AEAD implementation using the lib-q-rocca-s crate.

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

/// Rocca-S AEAD implementation wrapper
pub struct RoccaSAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_rocca_s::RoccaSAead,
}

impl RoccaSAead {
    /// Create a new Rocca-S AEAD instance
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::RoccaS)
                .expect("Rocca-S metadata not found"),
            inner: lib_q_rocca_s::RoccaSAead::new(),
        }
    }
}

impl Aead for RoccaSAead {
    fn encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        crate::security::validation::validate_plaintext(plaintext)?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        #[cfg(feature = "rocca-s")]
        {
            self.inner
                .encrypt(key, nonce, plaintext, Some(associated_data))
        }

        #[cfg(not(feature = "rocca-s"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Rocca-S AEAD implementation requires 'rocca-s' feature",
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
        self.validate_key(key)?;
        self.validate_nonce(nonce)?;
        self.validate_ciphertext_size(ciphertext.len())?;
        crate::security::validation::validate_ciphertext(ciphertext)?;

        let associated_data = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(associated_data)?;

        #[cfg(feature = "rocca-s")]
        {
            self.inner
                .decrypt(key, nonce, ciphertext, Some(associated_data))
        }

        #[cfg(not(feature = "rocca-s"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Rocca-S AEAD implementation requires 'rocca-s' feature",
            })
        }
    }
}

impl AeadDecryptSemantic for RoccaSAead {
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

        #[cfg(feature = "rocca-s")]
        {
            self.inner
                .decrypt_semantic(key, nonce, ciphertext, Some(associated_data))
        }

        #[cfg(not(feature = "rocca-s"))]
        {
            Err(lib_q_core::Error::NotImplemented {
                feature: "Rocca-S AEAD implementation requires 'rocca-s' feature",
            })
        }
    }
}

impl AeadWithMetadata for RoccaSAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for RoccaSAead {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the plugin trait.
impl crate::plugin::AeadPlugin for RoccaSAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RoccaS
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::RoccaS).expect("Metadata not found for algorithm")
    }

    fn name(&self) -> &'static str {
        "Rocca-S AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "High-throughput AES-round AEAD (IETF draft-nakano-rocca-s)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rocca_s_creation() {
        let aead = RoccaSAead::new();
        assert_eq!(aead.algorithm(), Algorithm::RoccaS);
        assert_eq!(aead.key_size(), 32);
        assert_eq!(aead.nonce_size(), 16);
        assert_eq!(aead.tag_size(), 32);
        assert_eq!(aead.security_level(), 1);
    }

    #[test]
    fn test_rocca_s_metadata() {
        let aead = RoccaSAead::new();
        let metadata = aead.metadata();
        assert_eq!(metadata.algorithm, Algorithm::RoccaS);
        assert_eq!(metadata.name, "Rocca-S");
        assert_eq!(metadata.key_size, 32);
        assert_eq!(metadata.nonce_size, 16);
        assert_eq!(metadata.tag_size, 32);
        assert_eq!(metadata.security_level, 1);
    }

    #[test]
    fn test_rocca_s_validation() {
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        assert!(aead.validate_key(&key).is_ok());
        let invalid_key = AeadKey::new(vec![0u8; 16]);
        assert!(aead.validate_key(&invalid_key).is_err());
        let nonce = Nonce::new(vec![0u8; 16]);
        assert!(aead.validate_nonce(&nonce).is_ok());
        let invalid_nonce = Nonce::new(vec![0u8; 12]);
        assert!(aead.validate_nonce(&invalid_nonce).is_err());
    }

    #[cfg(feature = "rocca-s")]
    #[test]
    fn test_rocca_s_encrypt_decrypt() {
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let plaintext = b"Hello, World!";
        let ad = b"metadata";

        let ciphertext = aead
            .encrypt(&key, &nonce, plaintext, Some(ad.as_slice()))
            .unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + aead.tag_size());

        let decrypted = aead
            .decrypt(&key, &nonce, &ciphertext, Some(ad.as_slice()))
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "rocca-s")]
    #[test]
    fn test_rocca_s_authentication_failure() {
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let ciphertext = aead.encrypt(&key, &nonce, b"Hello, World!", None).unwrap();
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;
        let result = aead.decrypt(&key, &nonce, &tampered, None);
        assert!(matches!(
            result,
            Err(lib_q_core::Error::VerificationFailed { .. })
        ));
    }

    #[cfg(feature = "rocca-s")]
    #[test]
    fn test_rocca_s_official_kat() {
        // IETF draft-nakano-rocca-s all-zero vector via the umbrella wrapper.
        let aead = RoccaSAead::new();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let ad = vec![0u8; 32];
        let pt = vec![0u8; 64];
        let ct = aead.encrypt(&key, &nonce, &pt, Some(&ad)).unwrap();
        let tag = &ct[64..];
        let expected_tag = [
            0x8D, 0xF9, 0x34, 0xD1, 0x48, 0x37, 0x10, 0xC9, 0x41, 0x0F, 0x6A, 0x08, 0x9C, 0x4C,
            0xED, 0x97, 0x91, 0x90, 0x1B, 0x7E, 0x2E, 0x66, 0x12, 0x06, 0x20, 0x2D, 0xB2, 0xCC,
            0x7A, 0x24, 0xA3, 0x86,
        ];
        assert_eq!(tag, expected_tag);
    }
}
