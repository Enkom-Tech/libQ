//! Romulus-M AEAD — registry-facing type.

use alloc::boxed::Box;
use alloc::vec::Vec;

use lib_q_core::{
    Aead,
    AeadKey,
    Algorithm,
    Nonce,
    Result,
};

use crate::metadata::{
    AeadMetadata,
    AeadWithMetadata,
};

/// Romulus-M (nonce-misuse-resistant AEAD) for the lib-Q AEAD registry.
pub struct RomulusMAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_romulus::RomulusMAead,
}

impl RomulusMAead {
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::RomulusM)
                .expect("Romulus-M metadata"),
            inner: lib_q_romulus::RomulusMAead::new(),
        }
    }
}

impl Aead for RomulusMAead {
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
        let ad = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(ad)?;
        crate::security::timing::protect_timing(|| {
            self.inner.encrypt(key, nonce, plaintext, Some(ad))
        })
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
        let ad = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(ad)?;
        crate::security::timing::protect_timing(|| {
            self.inner.decrypt(key, nonce, ciphertext, Some(ad))
        })
    }
}

impl AeadWithMetadata for RomulusMAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for RomulusMAead {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::plugin::AeadPlugin for RomulusMAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RomulusM
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::RomulusM).expect("Romulus-M metadata")
    }

    fn name(&self) -> &'static str {
        "Romulus-M"
    }

    fn version(&self) -> &'static str {
        "1.3.0"
    }

    fn description(&self) -> &'static str {
        "Romulus-M misuse-resistant AEAD (SKINNY-128-384+), 128-bit key/nonce/tag"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn romulus_m_metadata_matches() {
        let a = RomulusMAead::new();
        assert_eq!(a.algorithm(), Algorithm::RomulusM);
        assert_eq!(a.key_size(), 16);
        assert_eq!(a.nonce_size(), 16);
        assert_eq!(a.tag_size(), 16);
    }

    #[test]
    fn romulus_m_roundtrip_registry() {
        let a = RomulusMAead::new();
        let key = AeadKey::new([7u8; 16].to_vec());
        let nonce = Nonce::new([8u8; 16].to_vec());
        let pt = b"hello-romulus-m";
        let ad = b"ad-bytes";
        let ct = a
            .encrypt(&key, &nonce, pt.as_slice(), Some(ad.as_slice()))
            .expect("encrypt");
        let out = a
            .decrypt(&key, &nonce, ct.as_slice(), Some(ad.as_slice()))
            .expect("decrypt");
        assert_eq!(out.as_slice(), pt.as_slice());
    }
}
