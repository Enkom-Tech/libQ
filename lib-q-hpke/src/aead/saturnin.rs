//! Saturnin AEAD implementation using lib-q-saturnin

#[cfg(all(feature = "alloc", feature = "saturnin"))]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "saturnin")]
use lib_q_saturnin::{
    Aead as LibQAead,
    AeadKey,
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

            let aead_key = AeadKey { data: key.to_vec() };
            let aead_nonce = Nonce {
                data: nonce.to_vec(),
            };

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

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
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

            // Validate ciphertext length (must be at least tag length)
            if ciphertext.len() < 16 {
                return Err(HpkeError::aead_error(
                    HpkeAead::Saturnin256,
                    AeadOperation::CiphertextValidation,
                    "Ciphertext too short",
                ));
            }

            let aead_key = AeadKey { data: key.to_vec() };
            let aead_nonce = Nonce {
                data: nonce.to_vec(),
            };

            self.aead
                .decrypt(&aead_key, &aead_nonce, ciphertext, Some(aad))
                .map_err(|e| {
                    HpkeError::aead_error(
                        HpkeAead::Saturnin256,
                        AeadOperation::Open,
                        format!("Saturnin decryption failed: {}", e),
                    )
                })
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
