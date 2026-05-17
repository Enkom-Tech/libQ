//! Security policy configuration for HPKE operations

#[cfg(feature = "alloc")]
use alloc::format;

use crate::error::{
    HpkeError,
    SecurityValidation,
};

/// Security policy configuration for HPKE operations
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityPolicy {
    /// Require constant-time operations for all cryptographic functions
    pub require_constant_time: bool,
    /// Validate all key material before use
    pub validate_key_material: bool,
    /// Reject zero keys for security
    pub enforce_zero_key_rejection: bool,
    /// Validate input lengths strictly
    pub strict_length_validation: bool,
    /// Enable side-channel protection
    pub enable_side_channel_protection: bool,
    /// Maximum key size allowed
    pub max_key_size: usize,
    /// Maximum nonce size allowed
    pub max_nonce_size: usize,
    /// Maximum ciphertext size allowed
    pub max_ciphertext_size: usize,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_constant_time: true,
            validate_key_material: true,
            enforce_zero_key_rejection: true,
            strict_length_validation: true,
            enable_side_channel_protection: true,
            max_key_size: 4096, // 4KB max key size (for post-quantum keys)
            max_nonce_size: 32, // 32 bytes max nonce size
            max_ciphertext_size: 1024 * 1024, // 1MB max ciphertext
        }
    }
}

impl SecurityPolicy {
    /// Create a strict security policy for high-security applications
    pub fn strict() -> Self {
        Self {
            require_constant_time: true,
            validate_key_material: true,
            enforce_zero_key_rejection: true,
            strict_length_validation: true,
            enable_side_channel_protection: true,
            max_key_size: 32,               // Conservative key size limit
            max_nonce_size: 16,             // Conservative nonce size limit
            max_ciphertext_size: 64 * 1024, // 64KB max ciphertext
        }
    }

    /// Create a permissive security policy for testing/development
    pub fn permissive() -> Self {
        Self {
            require_constant_time: false,
            validate_key_material: false,
            enforce_zero_key_rejection: false,
            strict_length_validation: false,
            enable_side_channel_protection: false,
            max_key_size: 128,
            max_nonce_size: 64,
            max_ciphertext_size: 10 * 1024 * 1024, // 10MB max ciphertext
        }
    }

    /// Validate key material according to policy
    pub fn validate_key(&self, key: &[u8], expected_len: usize) -> Result<(), HpkeError> {
        if !self.validate_key_material {
            return Ok(());
        }

        if self.strict_length_validation && key.len() != expected_len {
            return Err(HpkeError::security_error(
                SecurityValidation::KeyLength,
                format!("Expected key length {}, got {}", expected_len, key.len()),
            ));
        }

        if key.len() > self.max_key_size {
            return Err(HpkeError::security_error(
                SecurityValidation::KeyLength,
                format!(
                    "Key too large: {} bytes (max: {})",
                    key.len(),
                    self.max_key_size
                ),
            ));
        }

        if self.enforce_zero_key_rejection && key.iter().all(|&b| b == 0) {
            return Err(HpkeError::security_error(
                SecurityValidation::ZeroKeyRejection,
                "Key material cannot be all zeros",
            ));
        }

        Ok(())
    }

    /// Validate nonce according to policy
    pub fn validate_nonce(&self, nonce: &[u8], expected_len: usize) -> Result<(), HpkeError> {
        if !self.validate_key_material {
            return Ok(());
        }

        if self.strict_length_validation && nonce.len() != expected_len {
            return Err(HpkeError::security_error(
                SecurityValidation::NonceLength,
                format!(
                    "Expected nonce length {}, got {}",
                    expected_len,
                    nonce.len()
                ),
            ));
        }

        if nonce.len() > self.max_nonce_size {
            return Err(HpkeError::security_error(
                SecurityValidation::NonceLength,
                format!(
                    "Nonce too large: {} bytes (max: {})",
                    nonce.len(),
                    self.max_nonce_size
                ),
            ));
        }

        Ok(())
    }

    /// Validate ciphertext according to policy
    pub fn validate_ciphertext(&self, ciphertext: &[u8]) -> Result<(), HpkeError> {
        if !self.validate_key_material {
            return Ok(());
        }

        if ciphertext.len() > self.max_ciphertext_size {
            return Err(HpkeError::security_error(
                SecurityValidation::CiphertextLength,
                format!(
                    "Ciphertext too large: {} bytes (max: {})",
                    ciphertext.len(),
                    self.max_ciphertext_size
                ),
            ));
        }

        Ok(())
    }
}

/// Get the default security policy
pub fn get_default_security_policy() -> SecurityPolicy {
    SecurityPolicy::default()
}

/// Get the strict security policy
pub fn get_strict_security_policy() -> SecurityPolicy {
    SecurityPolicy::strict()
}

/// Get the permissive security policy
pub fn get_permissive_security_policy() -> SecurityPolicy {
    SecurityPolicy::permissive()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn permissive_policy_skips_all_validation_paths() {
        let policy = SecurityPolicy::permissive();

        // Wrong length, oversized, and zero key all pass when validation is disabled.
        assert!(policy.validate_key(&[], 32).is_ok());
        assert!(policy.validate_key(&vec![0u8; 10_000], 32).is_ok());
        assert!(policy.validate_key(&[0u8; 32], 32).is_ok());

        assert!(policy.validate_nonce(&[], 16).is_ok());
        assert!(policy.validate_nonce(&vec![1u8; 10_000], 16).is_ok());
        assert!(policy.validate_ciphertext(&vec![2u8; 20_000_000]).is_ok());
    }

    #[test]
    fn strict_policy_enforces_nonce_and_ciphertext_limits() {
        let policy = SecurityPolicy::strict();

        let nonce_too_large = vec![1u8; 17];
        let nonce_err = policy.validate_nonce(&nonce_too_large, 17).unwrap_err();
        assert!(matches!(
            nonce_err,
            HpkeError::SecurityError {
                validation: SecurityValidation::NonceLength,
                ..
            }
        ));

        let ciphertext_too_large = vec![1u8; (64 * 1024) + 1];
        let ct_err = policy
            .validate_ciphertext(&ciphertext_too_large)
            .unwrap_err();
        assert!(matches!(
            ct_err,
            HpkeError::SecurityError {
                validation: SecurityValidation::CiphertextLength,
                ..
            }
        ));
    }
}
