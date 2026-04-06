//! lib-Q AEAD provider: implements [`AeadOperations`](lib_q_core::api::AeadOperations) for the AEAD registry.
//!
//! Mirrors the pattern used by `lib-q-hash` (`LibQHashProvider`) and `lib-q-kem` (`LibQKemProvider`).

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use lib_q_core::api::{
    AeadOperations,
    Algorithm,
    AlgorithmCategory,
    CryptoProvider,
    HashOperations,
    KemOperations,
    SignatureOperations,
};
#[cfg(feature = "alloc")]
use lib_q_core::error::Result;
#[cfg(feature = "alloc")]
use lib_q_core::security::SecurityValidator;
#[cfg(feature = "alloc")]
use lib_q_core::traits::{
    AeadKey,
    Nonce,
};

#[cfg(feature = "alloc")]
use crate::{
    Aead,
    create_aead,
};

/// Registry-backed AEAD provider for integration with `lib-q-core` contexts.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct LibQAeadProvider {
    security_validator: SecurityValidator,
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for LibQAeadProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LibQAeadProvider")
            .field("security_validator", &"<SecurityValidator>")
            .finish()
    }
}

#[cfg(feature = "alloc")]
impl LibQAeadProvider {
    /// Create a new AEAD provider with security validation initialized.
    pub fn new() -> Result<Self> {
        Ok(Self {
            security_validator: SecurityValidator::new()?,
        })
    }

    /// Security validator used for input checks.
    pub fn security_validator(&self) -> &SecurityValidator {
        &self.security_validator
    }
}

#[cfg(feature = "alloc")]
impl AeadOperations for LibQAeadProvider {
    fn encrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Aead)?;
        self.security_validator
            .validate_key_material(key.as_bytes())?;
        self.security_validator.validate_nonce(nonce.as_bytes())?;
        self.security_validator.validate_message(plaintext)?;
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        let aead = create_aead(algorithm)?;
        Aead::encrypt(&*aead, key, nonce, plaintext, associated_data)
    }

    fn decrypt(
        &self,
        algorithm: Algorithm,
        key: &AeadKey,
        nonce: &Nonce,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Aead)?;
        self.security_validator
            .validate_key_material(key.as_bytes())?;
        self.security_validator.validate_nonce(nonce.as_bytes())?;
        // AEAD ciphertexts are variable-length; do not use `validate_ciphertext` (KEM-only sizes).
        if ciphertext.is_empty() {
            return Err(lib_q_core::Error::InvalidCiphertextSize {
                expected: 1,
                actual: 0,
            });
        }
        self.security_validator.validate_message(ciphertext)?;
        if let Some(ad) = associated_data {
            self.security_validator.validate_message(ad)?;
        }

        let aead = create_aead(algorithm)?;
        Aead::decrypt(&*aead, key, nonce, ciphertext, associated_data)
    }
}

#[cfg(feature = "alloc")]
impl CryptoProvider for LibQAeadProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        None
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        None
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        None
    }

    fn aead(&self) -> Option<&dyn AeadOperations> {
        Some(self)
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    use lib_q_core::{
        Algorithm,
        Error,
    };

    use super::*;

    #[test]
    fn test_libq_aead_provider_creation() {
        assert!(LibQAeadProvider::new().is_ok());
    }

    #[test]
    fn test_non_aead_algorithm_rejected() {
        let provider = LibQAeadProvider::new().unwrap();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let result = provider.encrypt(Algorithm::MlKem512, &key, &nonce, b"test", None);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidAlgorithm { .. })));
    }

    #[test]
    fn test_provider_security_validator_accessor() {
        let provider = LibQAeadProvider::new().unwrap();
        let _validator = provider.security_validator();
    }

    #[test]
    fn test_non_aead_algorithm_rejected_on_decrypt() {
        let provider = LibQAeadProvider::new().unwrap();
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);
        let result = provider.decrypt(Algorithm::MlKem512, &key, &nonce, b"ciphertext", None);
        assert!(matches!(result, Err(Error::InvalidAlgorithm { .. })));
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_empty_ciphertext_rejected_before_backend_decrypt() {
        let provider = LibQAeadProvider::new().unwrap();
        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, b) in key_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x17).wrapping_add(0x41);
        }
        for (i, b) in nonce_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x29).wrapping_add(0x13);
        }
        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let result = provider.decrypt(Algorithm::Shake256Aead, &key, &nonce, b"", None);
        assert!(matches!(
            result,
            Err(Error::InvalidCiphertextSize {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_aead_roundtrip_via_provider() {
        let provider = LibQAeadProvider::new().unwrap();
        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, b) in key_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        for (i, b) in nonce_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }
        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let pt = b"provider roundtrip";
        let ad = b"ad";

        let ct = AeadOperations::encrypt(
            &provider,
            Algorithm::Shake256Aead,
            &key,
            &nonce,
            pt.as_slice(),
            Some(ad.as_slice()),
        )
        .expect("encrypt");
        let out = AeadOperations::decrypt(
            &provider,
            Algorithm::Shake256Aead,
            &key,
            &nonce,
            &ct,
            Some(ad.as_slice()),
        )
        .expect("decrypt");
        assert_eq!(out.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_crypto_provider_trait_exposes_only_aead_operations() {
        let provider = LibQAeadProvider::new().unwrap();
        let crypto_provider: &dyn CryptoProvider = &provider;
        assert!(crypto_provider.kem().is_none());
        assert!(crypto_provider.signature().is_none());
        assert!(crypto_provider.hash().is_none());
        assert!(crypto_provider.aead().is_some());
    }
}
