//! SHAKE256 AEAD for HPKE (`HpkeAead::Shake256`).
//!
//! Wraps concrete [`lib_q_aead::Shake256Aead`]. HPKE [`crate::aead::traits::Aead::open`]
//! is a thin wrapper over [`Shake256AeadImpl::decrypt_semantic`] (Layer B), mirroring
//! [`super::saturnin::SaturninAeadImpl`].

#[cfg(all(feature = "alloc", feature = "shake256"))]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "shake256")]
use lib_q_aead::Shake256Aead;
#[cfg(feature = "shake256")]
use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Nonce,
};

use crate::error::{
    AeadOperation,
    HpkeError,
};
use crate::types::*;

/// SHAKE256 AEAD implementation using concrete `lib-q-aead` [`Shake256Aead`].
pub struct Shake256AeadImpl {
    #[cfg(feature = "shake256")]
    aead: Shake256Aead,
}

impl Shake256AeadImpl {
    /// Create a new SHAKE256 AEAD implementation
    pub fn new() -> Result<Self, HpkeError> {
        #[cfg(feature = "shake256")]
        {
            Ok(Self {
                aead: Shake256Aead::new(),
            })
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(HpkeError::feature_not_enabled("SHAKE256 AEAD support"))
        }
    }

    /// Validate key, nonce, and minimum ciphertext length for SHAKE256 HPKE paths.
    #[cfg(feature = "shake256")]
    fn prepare_shake256_open(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<(AeadKey, Nonce), HpkeError> {
        if key.len() != 32 {
            return Err(HpkeError::aead_error(
                HpkeAead::Shake256,
                AeadOperation::KeyValidation,
                format!(
                    "Invalid key length for SHAKE256: expected 32 bytes, got {}",
                    key.len()
                ),
            ));
        }

        if key.iter().all(|&b| b == 0) {
            return Err(HpkeError::aead_error(
                HpkeAead::Shake256,
                AeadOperation::KeyValidation,
                "Key material cannot be all zeros",
            ));
        }

        if nonce.len() != 16 {
            return Err(HpkeError::aead_error(
                HpkeAead::Shake256,
                AeadOperation::NonceValidation,
                format!(
                    "Invalid nonce length for SHAKE256: expected 16 bytes, got {}",
                    nonce.len()
                ),
            ));
        }

        if ciphertext.len() < 32 {
            return Err(HpkeError::aead_error(
                HpkeAead::Shake256,
                AeadOperation::CiphertextValidation,
                "Ciphertext too short",
            ));
        }

        Ok((AeadKey::new(key.to_vec()), Nonce::new(nonce.to_vec())))
    }

    /// Layer B decrypt: operational failures are [`Err`]; authentication failure is
    /// [`DecryptSemanticOutcome::AuthenticationFailed`] in the [`Ok`] arm.
    #[cfg(feature = "shake256")]
    pub fn decrypt_semantic(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<DecryptSemanticOutcome, HpkeError> {
        let (aead_key, aead_nonce) = Self::prepare_shake256_open(key, nonce, ciphertext)?;
        self.aead
            .decrypt_semantic(&aead_key, &aead_nonce, ciphertext, Some(aad))
            .map_err(|e| {
                HpkeError::aead_error(
                    HpkeAead::Shake256,
                    AeadOperation::Open,
                    format!("SHAKE256 semantic decrypt failed: {}", e),
                )
            })
    }
}

impl crate::aead::traits::Aead for Shake256AeadImpl {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "shake256")]
        {
            if key.len() != 32 {
                return Err(HpkeError::aead_error(
                    HpkeAead::Shake256,
                    AeadOperation::KeyValidation,
                    format!(
                        "Invalid key length for SHAKE256: expected 32 bytes, got {}",
                        key.len()
                    ),
                ));
            }

            if key.iter().all(|&b| b == 0) {
                return Err(HpkeError::aead_error(
                    HpkeAead::Shake256,
                    AeadOperation::KeyValidation,
                    "Key material cannot be all zeros",
                ));
            }

            if nonce.len() != 16 {
                return Err(HpkeError::aead_error(
                    HpkeAead::Shake256,
                    AeadOperation::NonceValidation,
                    format!(
                        "Invalid nonce length for SHAKE256: expected 16 bytes, got {}",
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
                        HpkeAead::Shake256,
                        AeadOperation::Seal,
                        format!("SHAKE256 encryption failed: {}", e),
                    )
                })
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(HpkeError::feature_not_enabled("SHAKE256 AEAD support"))
        }
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        #[cfg(feature = "shake256")]
        {
            match self.decrypt_semantic(key, nonce, aad, ciphertext)? {
                DecryptSemanticOutcome::Success(p) => Ok(Vec::clone(&*p)),
                DecryptSemanticOutcome::AuthenticationFailed => Err(HpkeError::aead_error(
                    HpkeAead::Shake256,
                    AeadOperation::Open,
                    String::from("SHAKE256 authentication failed"),
                )),
            }
        }

        #[cfg(not(feature = "shake256"))]
        {
            Err(HpkeError::feature_not_enabled("SHAKE256 AEAD support"))
        }
    }
}

/// Create a SHAKE256 AEAD implementation
pub fn create_shake256_aead() -> Result<Shake256AeadImpl, HpkeError> {
    Shake256AeadImpl::new()
}

/// Check if SHAKE256 AEAD is available
pub fn is_shake256_available() -> bool {
    #[cfg(feature = "shake256")]
    {
        true
    }
    #[cfg(not(feature = "shake256"))]
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
    fn test_shake256_availability() {
        let available = is_shake256_available();
        #[cfg(feature = "shake256")]
        assert!(available);
        #[cfg(not(feature = "shake256"))]
        assert!(!available);
    }

    #[test]
    fn test_shake256_creation() {
        let result = Shake256AeadImpl::new();
        #[cfg(feature = "shake256")]
        assert!(result.is_ok());
        #[cfg(not(feature = "shake256"))]
        assert!(result.is_err());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_operations() {
        let aead = Shake256AeadImpl::new().unwrap();

        let key = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];
        let nonce = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);

        let decrypted = aead.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_decrypt_semantic_auth_failure() {
        let aead = Shake256AeadImpl::new().unwrap();
        let key = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];
        let nonce = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let aad = b"metadata";
        let plaintext = b"Hello, World!";
        let mut ct = aead.seal(&key, &nonce, aad, plaintext).unwrap();
        *ct.last_mut().expect("tag byte") ^= 1;
        let out = aead.decrypt_semantic(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_invalid_key_length() {
        let aead = Shake256AeadImpl::new().unwrap();

        let invalid_key = vec![1u8; 16];
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
            assert_eq!(algorithm, HpkeAead::Shake256);
            assert_eq!(operation, AeadOperation::KeyValidation);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_invalid_nonce_length() {
        let aead = Shake256AeadImpl::new().unwrap();

        let key = vec![1u8; 32];
        let invalid_nonce = vec![2u8; 12];
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
            assert_eq!(algorithm, HpkeAead::Shake256);
            assert_eq!(operation, AeadOperation::NonceValidation);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_zero_key() {
        let aead = Shake256AeadImpl::new().unwrap();

        let zero_key = vec![0u8; 32];
        let nonce = vec![2u8; 16];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let result = aead.seal(&zero_key, &nonce, aad, plaintext);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Shake256);
            assert_eq!(operation, AeadOperation::KeyValidation);
        } else {
            panic!("Expected AeadError");
        }
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_shake256_authentication_failure() {
        let aead = Shake256AeadImpl::new().unwrap();

        let key = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];
        let nonce = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plaintext = b"Hello, World!";
        let aad = b"metadata";

        let ciphertext = aead.seal(&key, &nonce, aad, plaintext).unwrap();

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;

        let result = aead.open(&key, &nonce, aad, &tampered);
        assert!(result.is_err());

        if let Err(HpkeError::AeadError {
            algorithm,
            operation,
            ..
        }) = result
        {
            assert_eq!(algorithm, HpkeAead::Shake256);
            assert_eq!(operation, AeadOperation::Open);
        } else {
            panic!("Expected AeadError");
        }
    }
}
