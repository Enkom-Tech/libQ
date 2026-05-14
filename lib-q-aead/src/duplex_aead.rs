//! Duplex-sponge AEAD wrapper.

#[cfg(feature = "alloc")]
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

/// Duplex-sponge AEAD (Keccak-f[1600]) — registry / HPKE-facing type.
pub struct DuplexSpongeAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_duplex_aead::DuplexSpongeAead,
}

impl DuplexSpongeAead {
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::DuplexSpongeAead)
                .expect("DuplexSpongeAead metadata"),
            inner: lib_q_duplex_aead::DuplexSpongeAead::new(),
        }
    }
}

impl Aead for DuplexSpongeAead {
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

impl AeadWithMetadata for DuplexSpongeAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for DuplexSpongeAead {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::plugin::AeadPlugin for DuplexSpongeAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::DuplexSpongeAead
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::DuplexSpongeAead)
            .expect("DuplexSpongeAead metadata")
    }

    fn name(&self) -> &'static str {
        "Duplex-Sponge-AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "Keccak-f[1600] duplex-sponge authenticated encryption"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches() {
        let a = DuplexSpongeAead::new();
        assert_eq!(a.algorithm(), Algorithm::DuplexSpongeAead);
        assert_eq!(a.key_size(), 32);
        assert_eq!(a.nonce_size(), 16);
        assert_eq!(a.tag_size(), 32);
    }
}
