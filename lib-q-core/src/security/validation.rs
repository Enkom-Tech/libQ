//! Centralized security validation for lib-Q
//!
//! This module provides the SecurityValidator that implements comprehensive
//! security validation for all cryptographic operations.

#[cfg(feature = "alloc")]
use alloc::string::ToString;

use super::{
    EntropyValidator,
    SecurityConstants,
    TimingValidator,
};
use crate::api::{
    Algorithm,
    AlgorithmCategory,
};
use crate::error::Result;

/// Centralized security validator for lib-Q
///
/// This validator provides comprehensive security validation for all cryptographic
/// operations, including algorithm validation, key validation, timing attack prevention,
/// and entropy validation.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct SecurityValidator {
    timing_validator: TimingValidator,
    entropy_validator: EntropyValidator,
    constants: SecurityConstants,
}

#[cfg(feature = "alloc")]
impl SecurityValidator {
    /// Create a new security validator
    ///
    /// # Returns
    ///
    /// A new instance of SecurityValidator with all validation components initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation component fails to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            timing_validator: TimingValidator::new()?,
            entropy_validator: EntropyValidator::new()?,
            constants: SecurityConstants::new(),
        })
    }

    /// Validate that an algorithm is appropriate for the given operation category
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate
    /// * `expected_category` - The expected algorithm category
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the algorithm supports the category, or an error if it doesn't.
    pub fn validate_algorithm_category(
        &self,
        algorithm: Algorithm,
        expected_category: AlgorithmCategory,
    ) -> Result<()> {
        if !algorithm.supports_category(expected_category) {
            return Err(crate::error::Error::InvalidAlgorithm {
                algorithm: "Algorithm category mismatch",
            });
        }
        Ok(())
    }

    /// Validate key size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate against
    /// * `key_data` - The key data to validate
    /// * `is_secret` - Whether this is a secret key (affects expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key size is correct, or an error if it's not.
    pub fn validate_key_size(
        &self,
        algorithm: Algorithm,
        key_data: &[u8],
        is_secret: bool,
    ) -> Result<()> {
        let expected_size = self.constants.get_expected_key_size(algorithm, is_secret)?;

        if key_data.len() != expected_size {
            return Err(crate::error::Error::InvalidKeySize {
                expected: expected_size,
                actual: key_data.len(),
            });
        }

        Ok(())
    }

    /// Validate that key material is not all zeros (security check)
    ///
    /// # Arguments
    ///
    /// * `key_data` - The key data to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key material is valid, or an error if it's not.
    pub fn validate_key_material(&self, key_data: &[u8]) -> Result<()> {
        if key_data.is_empty() {
            return Err(crate::error::Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        // Check for zero key
        if key_data.iter().all(|&b| b == 0) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key material cannot be all zeros".to_string(),
            });
        }

        // Check for all-ones key
        if key_data.iter().all(|&b| b == 0xFF) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key material cannot be all ones".to_string(),
            });
        }

        // Validate entropy
        self.entropy_validator.validate_key_entropy(key_data)?;

        Ok(())
    }

    /// Validate public key for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate against
    /// * `key_data` - The public key data to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the public key is valid, or an error if it's not.
    pub fn validate_public_key(&self, algorithm: Algorithm, key_data: &[u8]) -> Result<()> {
        self.validate_key_size(algorithm, key_data, false)?;
        self.validate_key_material(key_data)?;
        Ok(())
    }

    /// Validate secret key for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate against
    /// * `key_data` - The secret key data to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the secret key is valid, or an error if it's not.
    pub fn validate_secret_key(&self, algorithm: Algorithm, key_data: &[u8]) -> Result<()> {
        self.validate_key_size(algorithm, key_data, true)?;
        self.validate_key_material(key_data)?;
        Ok(())
    }

    /// Validate message size for cryptographic operations
    ///
    /// # Arguments
    ///
    /// * `message` - The message to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the message size is valid, or an error if it's not.
    pub fn validate_message(&self, message: &[u8]) -> Result<()> {
        if message.len() > self.constants.max_message_size() {
            return Err(crate::error::Error::InvalidMessageSize {
                max: self.constants.max_message_size(),
                actual: message.len(),
            });
        }
        Ok(())
    }

    /// Validate nonce size and uniqueness for AEAD operations
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the nonce is valid, or an error if it's not.
    pub fn validate_nonce(&self, nonce: &[u8]) -> Result<()> {
        if nonce.len() != self.constants.standard_nonce_size() {
            return Err(crate::error::Error::InvalidNonceSize {
                expected: self.constants.standard_nonce_size(),
                actual: nonce.len(),
            });
        }

        // Check for zero nonce
        if nonce.iter().all(|&b| b == 0) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "nonce".to_string(),
                reason: "Nonce cannot be all zeros".to_string(),
            });
        }

        Ok(())
    }

    /// Validate ciphertext size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate against
    /// * `ciphertext` - The ciphertext to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the ciphertext size is valid, or an error if it's not.
    pub fn validate_ciphertext(&self, algorithm: Algorithm, ciphertext: &[u8]) -> Result<()> {
        if ciphertext.is_empty() {
            return Err(crate::error::Error::InvalidCiphertextSize {
                expected: 1,
                actual: 0,
            });
        }

        let expected_size = self.constants.get_expected_ciphertext_size(algorithm)?;
        if ciphertext.len() != expected_size {
            return Err(crate::error::Error::InvalidCiphertextSize {
                expected: expected_size,
                actual: ciphertext.len(),
            });
        }

        Ok(())
    }

    /// Validate signature size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to validate against
    /// * `signature` - The signature to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the signature size is valid, or an error if it's not.
    pub fn validate_signature(&self, algorithm: Algorithm, signature: &[u8]) -> Result<()> {
        if signature.is_empty() {
            return Err(crate::error::Error::InvalidSignatureSize {
                expected: 1,
                actual: 0,
            });
        }

        let expected_size = self.constants.get_expected_signature_size(algorithm)?;
        if signature.len() != expected_size {
            return Err(crate::error::Error::InvalidSignatureSize {
                expected: expected_size,
                actual: signature.len(),
            });
        }

        Ok(())
    }

    /// Validate randomness for cryptographic operations
    ///
    /// # Arguments
    ///
    /// * `randomness` - The randomness to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the randomness is valid, or an error if it's not.
    pub fn validate_randomness(&self, randomness: &[u8]) -> Result<()> {
        if randomness.len() < self.constants.min_randomness_size() {
            return Err(crate::error::Error::InvalidKeySize {
                expected: self.constants.min_randomness_size(),
                actual: randomness.len(),
            });
        }

        self.validate_key_material(randomness)?;
        Ok(())
    }

    /// Perform constant-time comparison of two byte slices
    ///
    /// # Arguments
    ///
    /// * `a` - First byte slice
    /// * `b` - Second byte slice
    ///
    /// # Returns
    ///
    /// Returns `true` if the slices are equal, `false` otherwise.
    /// The comparison is performed in constant time to prevent timing attacks.
    pub fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        self.timing_validator.constant_time_compare(a, b)
    }

    /// Get immutable access to the entropy validator
    ///
    /// This method provides access to the entropy validator for configuration
    /// and inspection purposes.
    pub fn entropy_validator(&self) -> &EntropyValidator {
        &self.entropy_validator
    }

    /// Get mutable access to the entropy validator
    ///
    /// This method provides mutable access to the entropy validator for
    /// configuration purposes. Use with caution in production environments.
    ///
    /// # Security Warning
    ///
    /// Disabling entropy validation reduces security. Only use this for
    /// testing scenarios with deterministic randomness.
    pub fn entropy_validator_mut(&mut self) -> &mut EntropyValidator {
        &mut self.entropy_validator
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_security_validator_creation() {
        let validator = SecurityValidator::new();
        assert!(
            validator.is_ok(),
            "SecurityValidator should be created successfully"
        );
    }

    #[test]
    fn test_validate_algorithm_category() {
        let validator = SecurityValidator::new().unwrap();

        // Test correct category
        let result =
            validator.validate_algorithm_category(Algorithm::MlKem512, AlgorithmCategory::Kem);
        assert!(result.is_ok(), "Should accept correct algorithm category");

        // Test incorrect category
        let result = validator
            .validate_algorithm_category(Algorithm::MlKem512, AlgorithmCategory::Signature);
        assert!(
            result.is_err(),
            "Should reject incorrect algorithm category"
        );
    }

    #[test]
    fn test_validate_key_material() {
        let validator = SecurityValidator::new().unwrap();

        // Test valid key (16 bytes to meet minimum entropy requirements)
        let valid_key = vec![
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7,
            0xF8, 0x09,
        ];
        let result = validator.validate_key_material(&valid_key);
        assert!(result.is_ok(), "Should accept valid key material");

        // Test zero key
        let zero_key = vec![0u8; 8];
        let result = validator.validate_key_material(&zero_key);
        assert!(result.is_err(), "Should reject zero key");

        // Test all-ones key
        let ones_key = vec![0xFFu8; 8];
        let result = validator.validate_key_material(&ones_key);
        assert!(result.is_err(), "Should reject all-ones key");

        // Test empty key
        let empty_key = vec![];
        let result = validator.validate_key_material(&empty_key);
        assert!(result.is_err(), "Should reject empty key");
    }

    #[test]
    fn test_validate_message() {
        let validator = SecurityValidator::new().unwrap();

        // Test valid message
        let valid_message = vec![1u8; 1000];
        let result = validator.validate_message(&valid_message);
        assert!(result.is_ok(), "Should accept valid message size");

        // Test oversized message
        let oversized_message = vec![1u8; 2 * 1024 * 1024]; // 2MB
        let result = validator.validate_message(&oversized_message);
        assert!(result.is_err(), "Should reject oversized message");
    }

    #[test]
    fn test_constant_time_compare() {
        let validator = SecurityValidator::new().unwrap();

        // Test equal slices
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert!(
            validator.constant_time_compare(&a, &b),
            "Should return true for equal slices"
        );

        // Test different slices
        let c = vec![1, 2, 3, 5];
        assert!(
            !validator.constant_time_compare(&a, &c),
            "Should return false for different slices"
        );

        // Test different length slices
        let d = vec![1, 2, 3];
        assert!(
            !validator.constant_time_compare(&a, &d),
            "Should return false for different length slices"
        );
    }
}
