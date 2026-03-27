//! Tweakable CTR AEAD wrapper.

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

/// Tweak AEAD — registry / HPKE-facing type.
pub struct TweakAead {
    metadata: &'static AeadMetadata,
    inner: lib_q_tweak_aead::TweakAead,
}

impl TweakAead {
    pub fn new() -> Self {
        Self {
            metadata: crate::metadata::get_metadata(Algorithm::TweakAead)
                .expect("TweakAead metadata"),
            inner: lib_q_tweak_aead::TweakAead::new(),
        }
    }
}

impl Aead for TweakAead {
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

impl AeadWithMetadata for TweakAead {
    fn metadata(&self) -> &'static AeadMetadata {
        self.metadata
    }
}

impl Default for TweakAead {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::plugin::AeadPlugin for TweakAead {
    fn algorithm(&self) -> Algorithm {
        Algorithm::TweakAead
    }

    fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
        Ok(Box::new(Self::new()))
    }

    fn metadata(&self) -> &'static AeadMetadata {
        crate::metadata::get_metadata(Algorithm::TweakAead).expect("TweakAead metadata")
    }

    fn name(&self) -> &'static str {
        "Tweak-AEAD"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }

    fn description(&self) -> &'static str {
        "Parallel tweakable-block CTR AEAD over Keccak-f[1600]"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_matches() {
        let a = TweakAead::new();
        assert_eq!(a.algorithm(), Algorithm::TweakAead);
        assert_eq!(a.key_size(), 32);
        assert_eq!(a.nonce_size(), 16);
        assert_eq!(a.tag_size(), 32);
    }
}
