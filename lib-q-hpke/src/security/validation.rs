//! Cryptographic validation utilities

#[cfg(feature = "alloc")]
use alloc::format;

use super::policy::get_default_security_policy;
use crate::error::{
    HpkeError,
    SecurityValidation,
};
use crate::types::*;

/// Cryptographic validator with security policy enforcement
pub struct CryptographicValidator {
    policy: crate::security::SecurityPolicy,
}

impl CryptographicValidator {
    /// Create a new validator with the given policy
    pub fn new(policy: crate::security::SecurityPolicy) -> Self {
        Self { policy }
    }

    /// Create a validator with the default security policy
    pub fn with_default_policy() -> Self {
        Self {
            policy: get_default_security_policy(),
        }
    }

    /// Validate KEM key material
    pub fn validate_kem_key(
        &self,
        kem: HpkeKem,
        key: &[u8],
        is_secret: bool,
    ) -> Result<(), HpkeError> {
        let expected_len = if is_secret {
            kem.secret_key_len()
        } else {
            kem.public_key_len()
        };

        self.policy.validate_key(key, expected_len)?;

        // Additional KEM-specific validations
        match kem {
            HpkeKem::MlKem512 => {
                if is_secret && key.len() != 1632 {
                    return Err(HpkeError::security_error(
                        SecurityValidation::KeyLength,
                        format!(
                            "ML-KEM-512 secret key must be 1632 bytes, got {}",
                            key.len()
                        ),
                    ));
                }
            }
            HpkeKem::MlKem768 => {
                if is_secret && key.len() != 2400 {
                    return Err(HpkeError::security_error(
                        SecurityValidation::KeyLength,
                        format!(
                            "ML-KEM-768 secret key must be 2400 bytes, got {}",
                            key.len()
                        ),
                    ));
                }
            }
            HpkeKem::MlKem1024 => {
                if is_secret && key.len() != 3168 {
                    return Err(HpkeError::security_error(
                        SecurityValidation::KeyLength,
                        format!(
                            "ML-KEM-1024 secret key must be 3168 bytes, got {}",
                            key.len()
                        ),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate KDF key material
    pub fn validate_kdf_key(&self, kdf: HpkeKdf, key: &[u8]) -> Result<(), HpkeError> {
        let expected_len = kdf.extract_len();
        self.policy.validate_key(key, expected_len)?;
        Ok(())
    }

    /// Validate AEAD key material
    pub fn validate_aead_key(&self, aead: HpkeAead, key: &[u8]) -> Result<(), HpkeError> {
        let expected_len = aead.key_len();
        self.policy.validate_key(key, expected_len)?;
        Ok(())
    }

    /// Validate AEAD nonce
    pub fn validate_aead_nonce(&self, aead: HpkeAead, nonce: &[u8]) -> Result<(), HpkeError> {
        let expected_len = aead.nonce_len();
        self.policy.validate_nonce(nonce, expected_len)?;
        Ok(())
    }

    /// Validate ciphertext
    pub fn validate_ciphertext(&self, ciphertext: &[u8]) -> Result<(), HpkeError> {
        self.policy.validate_ciphertext(ciphertext)?;
        Ok(())
    }

    /// Validate input sanitization
    pub fn validate_input_sanitization(&self, input: &[u8], name: &str) -> Result<(), HpkeError> {
        if input.is_empty() {
            return Err(HpkeError::security_error(
                SecurityValidation::InputSanitization,
                format!("{} cannot be empty", name),
            ));
        }

        // Check for potential buffer overflow patterns
        if input.len() > 1024 * 1024 {
            return Err(HpkeError::security_error(
                SecurityValidation::InputSanitization,
                format!("{} too large: {} bytes", name, input.len()),
            ));
        }

        Ok(())
    }
}

/// Convenience functions for common validations
pub fn validate_kem_key(kem: HpkeKem, key: &[u8], is_secret: bool) -> Result<(), HpkeError> {
    let validator = CryptographicValidator::with_default_policy();
    validator.validate_kem_key(kem, key, is_secret)
}

/// Validate AEAD key length and properties
pub fn validate_aead_key(aead: HpkeAead, key: &[u8]) -> Result<(), HpkeError> {
    let validator = CryptographicValidator::with_default_policy();
    validator.validate_aead_key(aead, key)
}

/// Validate AEAD nonce length and properties
pub fn validate_aead_nonce(aead: HpkeAead, nonce: &[u8]) -> Result<(), HpkeError> {
    let validator = CryptographicValidator::with_default_policy();
    validator.validate_aead_nonce(aead, nonce)
}

/// Validate ciphertext properties
pub fn validate_ciphertext(ciphertext: &[u8]) -> Result<(), HpkeError> {
    let validator = CryptographicValidator::with_default_policy();
    validator.validate_ciphertext(ciphertext)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn validate_kem_secret_keys_accepts_expected_lengths() {
        let validator = CryptographicValidator::with_default_policy();

        assert!(
            validator
                .validate_kem_key(HpkeKem::MlKem512, &[1u8; 1632], true)
                .is_ok()
        );
        assert!(
            validator
                .validate_kem_key(HpkeKem::MlKem768, &[1u8; 2400], true)
                .is_ok()
        );
        assert!(
            validator
                .validate_kem_key(HpkeKem::MlKem1024, &[1u8; 3168], true)
                .is_ok()
        );
    }

    #[test]
    fn validate_kem_secret_keys_reject_wrong_lengths() {
        let validator = CryptographicValidator::with_default_policy();

        let err_512 = validator
            .validate_kem_key(HpkeKem::MlKem512, &[1u8; 1631], true)
            .unwrap_err();
        assert!(matches!(err_512, HpkeError::SecurityError { .. }));

        let err_768 = validator
            .validate_kem_key(HpkeKem::MlKem768, &[1u8; 2399], true)
            .unwrap_err();
        assert!(matches!(err_768, HpkeError::SecurityError { .. }));

        let err_1024 = validator
            .validate_kem_key(HpkeKem::MlKem1024, &[1u8; 3167], true)
            .unwrap_err();
        assert!(matches!(err_1024, HpkeError::SecurityError { .. }));
    }

    #[test]
    fn validate_kdf_and_convenience_functions() {
        let validator = CryptographicValidator::with_default_policy();

        assert!(
            validator
                .validate_kdf_key(HpkeKdf::HkdfShake128, &[5u8; 16])
                .is_ok()
        );
        assert!(
            validator
                .validate_kdf_key(HpkeKdf::HkdfShake256, &[5u8; 32])
                .is_ok()
        );

        assert!(validate_aead_key(HpkeAead::Saturnin256, &[7u8; 32]).is_ok());
        assert!(validate_aead_nonce(HpkeAead::Saturnin256, &[9u8; 16]).is_ok());
        assert!(validate_ciphertext(&[1u8; 64]).is_ok());
        assert!(validate_kem_key(HpkeKem::MlKem512, &[2u8; 800], false).is_ok());
    }

    #[test]
    fn input_sanitization_rejects_empty_and_huge_inputs() {
        let validator = CryptographicValidator::with_default_policy();

        let empty = validator.validate_input_sanitization(&[], "payload");
        assert!(matches!(empty, Err(HpkeError::SecurityError { .. })));

        let huge = vec![1u8; (1024 * 1024) + 1];
        let too_large = validator.validate_input_sanitization(&huge, "payload");
        assert!(matches!(too_large, Err(HpkeError::SecurityError { .. })));
    }
}
