//! Input validation and sanitization
//!
//! This module provides comprehensive input validation functions to ensure
//! that all inputs to cryptographic operations are safe and valid.

use lib_q_core::{
    Error,
    Result,
};

/// Input validation configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationConfig {
    /// Maximum key size in bytes
    pub max_key_size: usize,
    /// Maximum nonce size in bytes
    pub max_nonce_size: usize,
    /// Maximum plaintext size in bytes
    pub max_plaintext_size: usize,
    /// Maximum ciphertext size in bytes
    pub max_ciphertext_size: usize,
    /// Maximum associated data size in bytes
    pub max_associated_data_size: usize,
    /// Enable strict validation (reject potentially dangerous inputs)
    pub strict: bool,
    /// Enable entropy validation for keys
    pub validate_key_entropy: bool,
    /// Enable nonce uniqueness validation
    pub validate_nonce_uniqueness: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_key_size: 1024,                      // 1KB
            max_nonce_size: 256,                     // 256 bytes
            max_plaintext_size: 1024 * 1024,         // 1MB
            max_ciphertext_size: 1024 * 1024 + 1024, // 1MB + overhead
            max_associated_data_size: 1024 * 1024,   // 1MB
            strict: true,
            validate_key_entropy: true,
            validate_nonce_uniqueness: false, // Disabled by default as it requires state
        }
    }
}

impl ValidationConfig {
    /// Create a strict validation configuration
    pub fn strict() -> Self {
        Self {
            max_key_size: 512,
            max_nonce_size: 128,
            max_plaintext_size: 512 * 1024, // 512KB
            max_ciphertext_size: 512 * 1024 + 1024,
            max_associated_data_size: 512 * 1024,
            strict: true,
            validate_key_entropy: true,
            validate_nonce_uniqueness: true,
        }
    }

    /// Create a permissive validation configuration
    pub fn permissive() -> Self {
        Self {
            max_key_size: 2048,
            max_nonce_size: 512,
            max_plaintext_size: 10 * 1024 * 1024, // 10MB
            max_ciphertext_size: 10 * 1024 * 1024 + 2048,
            max_associated_data_size: 10 * 1024 * 1024,
            strict: false,
            validate_key_entropy: false,
            validate_nonce_uniqueness: false,
        }
    }
}

/// Input validator
#[derive(Clone)]
pub struct InputValidator {
    config: ValidationConfig,
}

impl InputValidator {
    /// Create a new input validator with default configuration
    pub fn new() -> Self {
        Self {
            config: ValidationConfig::default(),
        }
    }

    /// Create a new input validator with custom configuration
    pub fn with_config(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a key
    pub fn validate_key(&self, key: &[u8]) -> Result<()> {
        // Check key size
        if key.is_empty() {
            return Err(Error::InvalidKeySize {
                expected: 1,
                actual: 0,
            });
        }

        if key.len() > self.config.max_key_size {
            return Err(Error::InvalidKeySize {
                expected: self.config.max_key_size,
                actual: key.len(),
            });
        }

        // Check for zero key
        if key.iter().all(|&b| b == 0) {
            return Err(Error::InvalidKeyFormat);
        }

        // Check for all-ones key
        if key.iter().all(|&b| b == 0xFF) {
            return Err(Error::InvalidKeyFormat);
        }

        // Check for repeated patterns
        if self.config.strict && self.has_repeated_pattern(key) {
            return Err(Error::InvalidKeyFormat);
        }

        // Validate entropy if enabled
        if self.config.validate_key_entropy &&
            self.config.strict &&
            !self.has_sufficient_entropy(key)
        {
            return Err(Error::InvalidKeyFormat);
        }

        Ok(())
    }

    /// Validate a nonce
    pub fn validate_nonce(&self, nonce: &[u8]) -> Result<()> {
        // Check nonce size
        if nonce.is_empty() {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        if nonce.len() > self.config.max_nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: self.config.max_nonce_size,
                actual: nonce.len(),
            });
        }

        // Check for zero nonce
        if nonce.iter().all(|&b| b == 0) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        // Check for all-ones nonce
        if nonce.iter().all(|&b| b == 0xFF) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        // Check for repeated patterns
        if self.config.strict && self.has_repeated_pattern(nonce) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        Ok(())
    }

    /// Validate plaintext
    pub fn validate_plaintext(&self, plaintext: &[u8]) -> Result<()> {
        // Check plaintext size
        if plaintext.len() > self.config.max_plaintext_size {
            return Err(Error::InvalidPlaintextSize {
                expected: self.config.max_plaintext_size,
                actual: plaintext.len(),
            });
        }

        // Check for suspicious patterns in strict mode
        if self.config.strict && self.has_suspicious_pattern(plaintext) {
            return Err(Error::InvalidPlaintextSize {
                expected: 0,
                actual: plaintext.len(),
            });
        }

        Ok(())
    }

    /// Validate ciphertext
    pub fn validate_ciphertext(&self, ciphertext: &[u8]) -> Result<()> {
        // Check ciphertext size
        if ciphertext.is_empty() {
            return Err(Error::InvalidCiphertextSize {
                expected: 1,
                actual: 0,
            });
        }

        if ciphertext.len() > self.config.max_ciphertext_size {
            return Err(Error::InvalidCiphertextSize {
                expected: self.config.max_ciphertext_size,
                actual: ciphertext.len(),
            });
        }

        Ok(())
    }

    /// Validate associated data
    pub fn validate_associated_data(&self, associated_data: &[u8]) -> Result<()> {
        // Check associated data size
        if associated_data.len() > self.config.max_associated_data_size {
            return Err(Error::InvalidMessageSize {
                max: self.config.max_associated_data_size,
                actual: associated_data.len(),
            });
        }

        Ok(())
    }

    /// Validate key size for a specific algorithm
    pub fn validate_key_size(&self, key_size: usize, expected_size: usize) -> Result<()> {
        if key_size != expected_size {
            return Err(Error::InvalidKeySize {
                expected: expected_size,
                actual: key_size,
            });
        }

        if key_size > self.config.max_key_size {
            return Err(Error::InvalidKeySize {
                expected: self.config.max_key_size,
                actual: key_size,
            });
        }

        Ok(())
    }

    /// Validate nonce size for a specific algorithm
    pub fn validate_nonce_size(&self, nonce_size: usize, expected_size: usize) -> Result<()> {
        if nonce_size != expected_size {
            return Err(Error::InvalidNonceSize {
                expected: expected_size,
                actual: nonce_size,
            });
        }

        if nonce_size > self.config.max_nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: self.config.max_nonce_size,
                actual: nonce_size,
            });
        }

        Ok(())
    }

    /// Check if data has repeated patterns
    fn has_repeated_pattern(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check for simple repeated patterns
        for pattern_len in 1..=data.len() / 2 {
            if !data.len().is_multiple_of(pattern_len) {
                continue;
            }

            let pattern = &data[0..pattern_len];
            let mut is_repeated = true;

            for chunk in data.chunks(pattern_len) {
                if chunk != pattern {
                    is_repeated = false;
                    break;
                }
            }

            if is_repeated {
                return true;
            }
        }

        false
    }

    /// Check if data has sufficient entropy
    fn has_sufficient_entropy(&self, data: &[u8]) -> bool {
        if data.len() < 16 {
            return false;
        }

        // Simple entropy check: count unique bytes
        let mut byte_counts = [0u8; 256];
        for &byte in data {
            byte_counts[byte as usize] = byte_counts[byte as usize].saturating_add(1);
        }

        let unique_bytes = byte_counts.iter().filter(|&&count| count > 0).count();

        // Require at least 50% unique bytes for good entropy
        unique_bytes >= data.len() / 2
    }

    /// Check if data has suspicious patterns
    fn has_suspicious_pattern(&self, data: &[u8]) -> bool {
        // Check for common attack patterns individually
        if data.windows(7).any(|window| window == b"<script") {
            return true;
        }
        if data.windows(7).any(|window| window == b"onload=") {
            return true;
        }
        if data.windows(8).any(|window| window == b"onerror=") {
            return true;
        }
        if data.windows(5).any(|window| window == b"eval(") {
            return true;
        }

        false
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global input validator with thread-safe access
#[cfg(feature = "std")]
use std::sync::{
    Arc,
    RwLock,
};

#[cfg(feature = "std")]
static GLOBAL_VALIDATOR: std::sync::OnceLock<Arc<RwLock<InputValidator>>> =
    std::sync::OnceLock::new();
#[cfg(not(feature = "std"))]
static GLOBAL_VALIDATOR: once_cell::sync::Lazy<spin::Mutex<InputValidator>> =
    once_cell::sync::Lazy::new(|| spin::Mutex::new(InputValidator::new()));

/// Get the global input validator
pub fn get_input_validator() -> InputValidator {
    #[cfg(feature = "std")]
    {
        GLOBAL_VALIDATOR
            .get_or_init(|| Arc::new(RwLock::new(InputValidator::new())))
            .read()
            .map(|guard| (*guard).clone())
            .unwrap_or_else(|_| InputValidator::new())
    }
    #[cfg(not(feature = "std"))]
    {
        GLOBAL_VALIDATOR.lock().clone()
    }
}

/// Set the global input validator
pub fn set_input_validator(validator: InputValidator) {
    #[cfg(feature = "std")]
    {
        if let Some(global_validator) = GLOBAL_VALIDATOR.get() {
            if let Ok(mut global) = global_validator.write() {
                *global = validator;
            }
        } else {
            let _ = GLOBAL_VALIDATOR.set(Arc::new(RwLock::new(validator)));
        }
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_VALIDATOR.lock() = validator;
    }
}

/// Convenience functions for global validation
/// Validate a key using the global validator
pub fn validate_key(key: &[u8]) -> Result<()> {
    get_input_validator().validate_key(key)
}

/// Validate a nonce using the global validator
pub fn validate_nonce(nonce: &[u8]) -> Result<()> {
    get_input_validator().validate_nonce(nonce)
}

/// Validate plaintext using the global validator
pub fn validate_plaintext(plaintext: &[u8]) -> Result<()> {
    get_input_validator().validate_plaintext(plaintext)
}

/// Validate ciphertext using the global validator
pub fn validate_ciphertext(ciphertext: &[u8]) -> Result<()> {
    get_input_validator().validate_ciphertext(ciphertext)
}

/// Validate associated data using the global validator
pub fn validate_associated_data(associated_data: &[u8]) -> Result<()> {
    get_input_validator().validate_associated_data(associated_data)
}

/// Validate key size using the global validator
pub fn validate_key_size(key_size: usize, expected_size: usize) -> Result<()> {
    get_input_validator().validate_key_size(key_size, expected_size)
}

/// Validate nonce size using the global validator
pub fn validate_nonce_size(nonce_size: usize, expected_size: usize) -> Result<()> {
    get_input_validator().validate_nonce_size(nonce_size, expected_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_defaults() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_key_size, 1024);
        assert_eq!(config.max_nonce_size, 256);
        assert_eq!(config.max_plaintext_size, 1024 * 1024);
        assert!(config.strict);
        assert!(config.validate_key_entropy);
    }

    #[test]
    fn test_validation_config_strict() {
        let config = ValidationConfig::strict();
        assert_eq!(config.max_key_size, 512);
        assert_eq!(config.max_nonce_size, 128);
        assert_eq!(config.max_plaintext_size, 512 * 1024);
        assert!(config.strict);
        assert!(config.validate_key_entropy);
        assert!(config.validate_nonce_uniqueness);
    }

    #[test]
    fn test_validation_config_permissive() {
        let config = ValidationConfig::permissive();
        assert_eq!(config.max_key_size, 2048);
        assert_eq!(config.max_nonce_size, 512);
        assert_eq!(config.max_plaintext_size, 10 * 1024 * 1024);
        assert!(!config.strict);
        assert!(!config.validate_key_entropy);
        assert!(!config.validate_nonce_uniqueness);
    }

    #[test]
    fn test_input_validator_creation() {
        let validator = InputValidator::new();
        assert!(validator.config.strict);
    }

    #[test]
    fn test_validate_key_empty() {
        let validator = InputValidator::new();
        assert!(validator.validate_key(&[]).is_err());
    }

    #[test]
    fn test_validate_key_zero() {
        let validator = InputValidator::new();
        assert!(validator.validate_key(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn test_validate_key_all_ones() {
        let validator = InputValidator::new();
        assert!(validator.validate_key(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_validate_key_repeated_pattern() {
        let validator = InputValidator::new();
        assert!(validator.validate_key(&[1, 2, 1, 2, 1, 2]).is_err());
    }

    #[test]
    fn test_validate_key_valid() {
        let validator = InputValidator::new();
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(validator.validate_key(&key).is_ok());
    }

    #[test]
    fn test_validate_nonce_empty() {
        let validator = InputValidator::new();
        assert!(validator.validate_nonce(&[]).is_err());
    }

    #[test]
    fn test_validate_nonce_zero() {
        let validator = InputValidator::new();
        assert!(validator.validate_nonce(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn test_validate_nonce_valid() {
        let validator = InputValidator::new();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(validator.validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_validate_plaintext_valid() {
        let validator = InputValidator::new();
        let plaintext = b"Hello, World!";
        assert!(validator.validate_plaintext(plaintext).is_ok());
    }

    #[test]
    fn test_validate_ciphertext_empty() {
        let validator = InputValidator::new();
        assert!(validator.validate_ciphertext(&[]).is_err());
    }

    #[test]
    fn test_validate_ciphertext_valid() {
        let validator = InputValidator::new();
        let ciphertext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(validator.validate_ciphertext(&ciphertext).is_ok());
    }

    #[test]
    fn test_validate_associated_data_valid() {
        let validator = InputValidator::new();
        let associated_data = b"metadata";
        assert!(validator.validate_associated_data(associated_data).is_ok());
    }

    #[test]
    fn test_validate_key_size() {
        let validator = InputValidator::new();
        assert!(validator.validate_key_size(32, 32).is_ok());
        assert!(validator.validate_key_size(16, 32).is_err());
    }

    #[test]
    fn test_validate_nonce_size() {
        let validator = InputValidator::new();
        assert!(validator.validate_nonce_size(16, 16).is_ok());
        assert!(validator.validate_nonce_size(12, 16).is_err());
    }

    #[test]
    fn test_has_repeated_pattern() {
        let validator = InputValidator::new();
        assert!(validator.has_repeated_pattern(&[1, 2, 1, 2, 1, 2]));
        assert!(!validator.has_repeated_pattern(&[1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_has_sufficient_entropy() {
        let validator = InputValidator::new();
        // High entropy data
        let high_entropy = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(validator.has_sufficient_entropy(&high_entropy));

        // Low entropy data
        let low_entropy = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert!(!validator.has_sufficient_entropy(&low_entropy));
    }

    #[test]
    fn test_has_suspicious_pattern() {
        let validator = InputValidator::new();
        assert!(validator.has_suspicious_pattern(b"<script>alert('xss')</script>"));
        assert!(!validator.has_suspicious_pattern(b"Hello, World!"));
    }

    #[test]
    fn test_global_validation_functions() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let plaintext = b"Hello, World!";
        let ciphertext = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let associated_data = b"metadata";

        assert!(validate_key(&key).is_ok());
        assert!(validate_nonce(&nonce).is_ok());
        assert!(validate_plaintext(plaintext).is_ok());
        assert!(validate_ciphertext(&ciphertext).is_ok());
        assert!(validate_associated_data(associated_data).is_ok());
        assert!(validate_key_size(32, 32).is_ok());
        assert!(validate_nonce_size(16, 16).is_ok());
    }
}
