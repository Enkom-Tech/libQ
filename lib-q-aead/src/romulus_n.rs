//! Romulus-N AEAD — registry-facing type.

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

use crate::metadata::{
    AeadMetadata,
    AeadWithMetadata,
};

/// Romulus-N (nonce-based AEAD) for the lib-Q AEAD registry.
pub struct RomulusNAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_romulus::RomulusNAead,
}

impl RomulusNAead {
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::RomulusN)
                .expect("Romulus-N metadata"),
            inner: lib_q_romulus::RomulusNAead::new(),
        }
    }
}

impl Aead for RomulusNAead {
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
        self.inner.encrypt(key, nonce, plaintext, Some(ad))
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
        self.inner.decrypt(key, nonce, ciphertext, Some(ad))
    }
}

impl AeadDecryptSemantic for RomulusNAead {
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
        let ad = associated_data.unwrap_or(&[]);
        crate::security::validation::validate_associated_data(ad)?;
        self.inner
            .decrypt_semantic(key, nonce, ciphertext, Some(ad))
    }
}

impl AeadWithMetadata for RomulusNAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for RomulusNAead {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::plugin::AeadPlugin for RomulusNAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RomulusN
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::RomulusN).expect("Romulus-N metadata")
    }

    fn name(&self) -> &'static str {
        "Romulus-N"
    }

    fn version(&self) -> &'static str {
        "1.3.0"
    }

    fn description(&self) -> &'static str {
        "Romulus-N nonce-based AEAD (SKINNY-128-384+), 128-bit key/nonce/tag"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn romulus_n_metadata_matches() {
        let a = RomulusNAead::new();
        assert_eq!(a.algorithm(), Algorithm::RomulusN);
        assert_eq!(a.key_size(), 16);
        assert_eq!(a.nonce_size(), 16);
        assert_eq!(a.tag_size(), 16);
    }
}
