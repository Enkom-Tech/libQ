//! Saturnin AEAD for HPKE (`HpkeAead::Saturnin256`).
//!
//! This module wraps [`SaturninAead`] from `lib-q-saturnin`.
//! Decryption follows that crate’s verification discipline (constant-time tag comparison and
//! symmetric decrypt scheduling as documented there and in `lib-q-saturnin/SECURITY.md`).
//!
//! HPKE’s [`crate::aead::traits::Aead::open`] remains **Layer A** [`Result`]-first;
//! it delegates to [`SaturninAeadImpl::decrypt_semantic`] (Layer B) for consistent mapping.
//! [`crate::providers::PostQuantumProvider`] / [`crate::providers::AeadProvider`] `open` stays
//! `Result`-only; use this concrete type for semantic outcomes.

#[cfg(all(feature = "alloc", feature = "saturnin"))]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

#[cfg(feature = "saturnin")]
use lib_q_saturnin::{
    Aead as LibQAead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Nonce,
    SaturninAead,
};

use crate::error::{
    AeadOperation,
    HpkeError,
};
use crate::types::*;

/// Saturnin AEAD implementation using lib-q-saturnin
pub struct SaturninAeadImpl {
    #[cfg(feature = "saturnin")]
    aead: SaturninAead,
}

impl SaturninAeadImpl {
    /// Create a new Saturnin AEAD implementation
    pub fn new() -> Result<Self, HpkeError> {
        #[cfg(feature = "saturnin")]
        {
            Ok(Self {
                aead: SaturninAead::new(),
            })
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(HpkeError::feature_not_enabled("Saturnin AEAD support"))
        }
    }

    /// Validate key, nonce, and minimum ciphertext length for Saturnin HPKE paths.
    #[cfg(feature = "saturnin")]
    fn prepare_saturnin_open(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<(AeadKey, Nonce), HpkeError> {
        if key.len() != 32 {
            return Err(HpkeError::aead_error(
                HpkeAead::Saturnin256,
                AeadOperation::KeyValidation,
                format!(
                    "Invalid key length for Saturnin: expected 32 bytes, got {}",
                    key.len()
                ),
            ));
        }

        if key.iter().all(|&b| b == 0) {
            return Err(HpkeError::aead_error(
                HpkeAead::Saturnin256,
                AeadOperation::KeyValidation,
                "Key material cannot be all zeros",
            ));
        }

        if nonce.len() != 16 {
            return Err(HpkeError::aead_error(
                HpkeAead::Saturnin256,
                AeadOperation::NonceValidation,
                format!(
                    "Invalid nonce length for Saturnin: expected 16 bytes, got {}",
                    nonce.len()
                ),
            ));
        }

        if ciphertext.len() < SaturninAead::tag_size() {
            return Err(HpkeError::aead_error(
                HpkeAead::Saturnin256,
                AeadOperation::CiphertextValidation,
                format!(
                    "Ciphertext too short: need at least {} bytes for Saturnin AEAD tag",
                    SaturninAead::tag_size()
                ),
            ));
        }

        Ok((AeadKey::new(key.to_vec()), Nonce::new(nonce.to_vec())))
    }

    /// Layer B decrypt: operational failures are [`Err`]; authentication failure is
    /// [`DecryptSemanticOutcome::AuthenticationFailed`] in the [`Ok`] arm.
    #[cfg(feature = "saturnin")]
    pub fn decrypt_semantic(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<DecryptSemanticOutcome, HpkeError> {
        let (aead_key, aead_nonce) = Self::prepare_saturnin_open(key, nonce, ciphertext)?;
        self.aead
            .decrypt_semantic(&aead_key, &aead_nonce, ciphertext, Some(aad))
            .map_err(|e| {
                HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::Open,
                    format!("Saturnin semantic decrypt failed: {}", e),
                )
            })
    }
}

impl crate::aead::traits::Aead for SaturninAeadImpl {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "saturnin")]
        {
            // Validate key length (Saturnin requires 32 bytes)
            if key.len() != 32 {
                return Err(HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::KeyValidation,
                    format!(
                        "Invalid key length for Saturnin: expected 32 bytes, got {}",
                        key.len()
                    ),
                ));
            }

            // Security validation: reject zero keys
            if key.iter().all(|&b| b == 0) {
                return Err(HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::KeyValidation,
                    "Key material cannot be all zeros",
                ));
            }

            // Validate nonce length (Saturnin requires 16 bytes)
            if nonce.len() != 16 {
                return Err(HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::NonceValidation,
                    format!(
                        "Invalid nonce length for Saturnin: expected 16 bytes, got {}",
                        nonce.len()
                    ),
                ));
            }

            let aead_key = AeadKey::new(key.to_vec());
            let aead_nonce = Nonce::new(nonce.to_vec());

            self.aead
                .encrypt(&aead_key, &aead_nonce, plaintext, Some(aad))
                .map_err(|e| {
                    HpkeError::aead_error(
                        HpkeAead::Saturnin256,
                        AeadOperation::Seal,
                        format!("Saturnin encryption failed: {}", e),
                    )
                })
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(HpkeError::feature_not_enabled("Saturnin AEAD support"))
        }
    }

    /// Decrypt and verify using [`SaturninAead`].
    ///
    /// Thin wrapper over [`SaturninAeadImpl::decrypt_semantic`]: maps
    /// [`DecryptSemanticOutcome::Success`] to `Ok` and authentication failure to `Err`.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "saturnin")]
        {
            match self.decrypt_semantic(key, nonce, aad, ciphertext)? {
                DecryptSemanticOutcome::Success(p) => Ok(Vec::clone(&*p)),
                DecryptSemanticOutcome::AuthenticationFailed => Err(HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::Open,
                    "Saturnin authentication failed".to_string(),
                )),
            }
        }

        #[cfg(not(feature = "saturnin"))]
        {
            Err(HpkeError::feature_not_enabled("Saturnin AEAD support"))
        }
    }
}

/// Create a Saturnin AEAD implementation
pub fn create_saturnin_aead() -> Result<SaturninAeadImpl, HpkeError> {
    SaturninAeadImpl::new()
}

/// Check if Saturnin AEAD is available
pub fn is_saturnin_available() -> bool {
    #[cfg(feature = "saturnin")]
    {
        true
    }
    #[cfg(not(feature = "saturnin"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;
    use crate::aead::traits::Aead;

    #[test]
    fn test_saturnin_availability() {
        let available = is_saturnin_available();
        #[cfg(feature = "saturnin")]
        assert!(available);
        #[cfg(not(feature = "saturnin"))]
        assert!(!available);
    }

    #[test]
    fn test_saturnin_creation() {
        let result = SaturninAeadImpl::new();
        #[cfg(feature = "saturnin")]
        assert!(result.is_ok());
        #[cfg(not(feature = "saturnin"))]
        assert!(result.is_err());
    }

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_operations() {
        let aead = SaturninAeadImpl::new().unwrap();

        let key = vec![1u8; 32];
        let nonce = vec![2u8; 16];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        // Encrypt
        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);

        // Decrypt
        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_decrypt_semantic_auth_failure() {
        let aead = SaturninAeadImpl::new().unwrap();
        let key = vec![3u8; 32];
        let nonce = vec![4u8; 16];
        let aad = b"aad";
        let plaintext = b"payload";
        let mut ct = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        *ct.last_mut().expect("tag byte") ^= 1;
        let out = aead.decrypt_semantic(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
    }

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_invalid_key_length() {
        let aead = SaturninAeadImpl::new().unwrap();

        let invalid_key = vec![1u8; 16]; // Wrong length
        let nonce = vec![2u8; 16];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let result = aead.seal(&invalid_key, &nonce, aad, plaintext);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Saturnin256);
            assert_eq!(operation, AeadOperation::KeyValidation);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[cfg(feature = "saturnin")]
    #[test]
    fn test_saturnin_invalid_nonce_length() {
        let aead = SaturninAeadImpl::new().unwrap();

        let key = vec![1u8; 32];
        let invalid_nonce = vec![2u8; 12]; // Wrong length
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let result = aead.seal(&key, &invalid_nonce, aad, plaintext);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Saturnin256);
            assert_eq!(operation, AeadOperation::NonceValidation);
        } else {
            panic!("Expected AeadError");
        }
    }
}
