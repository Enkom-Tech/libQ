//! Entropy validation utilities
//!
//! This module provides utilities to validate the entropy quality of cryptographic
//! inputs such as keys and randomness.

#[cfg(feature = "alloc")]
use alloc::string::ToString;

use crate::error::Result;

/// Entropy validator for cryptographic inputs
///
/// This validator provides utilities to validate the entropy quality of
/// cryptographic inputs to ensure they meet security requirements.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct EntropyValidator {
    min_entropy_bits: usize,
    enable_entropy_validation: bool,
}

#[cfg(feature = "alloc")]
impl EntropyValidator {
    /// Create a new entropy validator
    ///
    /// # Returns
    ///
    /// A new instance of EntropyValidator with default entropy requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if the validator fails to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            min_entropy_bits: 128, // Minimum 128 bits of entropy
            enable_entropy_validation: true,
        })
    }

    /// Validate key entropy
    ///
    /// This function validates that a key has sufficient entropy to be
    /// cryptographically secure.
    ///
    /// # Arguments
    ///
    /// * `key_data` - The key data to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key has sufficient entropy, or an error if it doesn't.
    pub fn validate_key_entropy(&self, key_data: &[u8]) -> Result<()> {
        if !self.enable_entropy_validation {
            return Ok(());
        }

        // Allow relaxed validation in testing environments
        #[cfg(feature = "relaxed_entropy_validation")]
        {
            self.validate_key_entropy_relaxed(key_data)
        }

        // Strict validation for production
        #[cfg(not(feature = "relaxed_entropy_validation"))]
        {
            self.validate_key_entropy_strict(key_data)
        }
    }

    /// Strict entropy validation for production environments.
    ///
    /// Pattern detection thresholds scale with key size so that legitimate
    /// NIST post-quantum keys (ML-DSA, SLH-DSA, FN-DSA) — which are structured
    /// algebraic objects, not uniformly random bytes — are never rejected by
    /// naive byte-level heuristics.
    #[cfg(not(feature = "relaxed_entropy_validation"))]
    fn validate_key_entropy_strict(&self, key_data: &[u8]) -> Result<()> {
        let min_key_length = self.min_entropy_bits / 8;
        if key_data.len() < min_key_length {
            return Err(crate::error::Error::InvalidKeySize {
                expected: min_key_length,
                actual: key_data.len(),
            });
        }

        if self.has_repeated_pattern(key_data) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key contains repeated patterns indicating low entropy".to_string(),
            });
        }

        if self.has_sequential_pattern(key_data) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key contains sequential patterns indicating low entropy".to_string(),
            });
        }

        if !self.has_sufficient_entropy(key_data) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key does not have sufficient entropy".to_string(),
            });
        }

        Ok(())
    }

    /// Relaxed entropy validation for testing environments
    ///
    /// This method implements relaxed entropy validation suitable for testing
    /// scenarios with deterministic randomness. It only performs basic checks
    /// to prevent obviously invalid keys while allowing deterministic patterns.
    #[cfg(feature = "relaxed_entropy_validation")]
    fn validate_key_entropy_relaxed(&self, key_data: &[u8]) -> Result<()> {
        // Check minimum key length (relaxed requirement)
        let min_key_length = 16; // Reduced from 128 bits to 16 bytes for testing
        if key_data.len() < min_key_length {
            return Err(crate::error::Error::InvalidKeySize {
                expected: min_key_length,
                actual: key_data.len(),
            });
        }

        // Only check for obviously invalid patterns (all zeros, all ones)
        if key_data.iter().all(|&b| b == 0) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key cannot be all zeros".to_string(),
            });
        }

        if key_data.iter().all(|&b| b == 0xFF) {
            return Err(crate::error::Error::InvalidKey {
                key_type: "key".to_string(),
                reason: "Key cannot be all ones".to_string(),
            });
        }

        // Skip pattern detection and entropy checks for testing
        Ok(())
    }

    /// Check if data is dominated by repeated 4-byte patterns.
    ///
    /// Isolated 4-byte repeats are statistically expected in keys longer than a
    /// few hundred bytes (birthday paradox on 2^32 patterns).  The threshold
    /// therefore scales: for keys ≤256 bytes any single repeat is suspicious; for
    /// larger keys we require that >12.5 % of 4-byte windows match some earlier
    /// window — which only occurs for truly degenerate inputs.
    #[cfg(not(feature = "relaxed_entropy_validation"))]
    fn has_repeated_pattern(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        let windows = data.len() - 3;
        let threshold = if data.len() <= 256 {
            2usize
        } else {
            windows / 8
        };

        let mut hits = 0usize;
        for i in 0..windows {
            let pattern = &data[i..i + 4];
            for j in i + 4..windows {
                if &data[j..j + 4] == pattern {
                    hits += 1;
                    if hits >= threshold {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if data is dominated by sequential (ascending / descending) bytes.
    ///
    /// A single 4-byte ascending run (e.g. `[0xA0, 0xA1, 0xA2, 0xA3]`) is
    /// expected with ≈6 % probability in an ML-DSA-65 secret key (4032 bytes).
    /// Rejecting on a single hit therefore produces unacceptable false-positive
    /// rates for legitimate PQ keys.
    ///
    /// Threshold: for keys ≤64 bytes, a single sequential run is flagged; for
    /// larger keys, the number of sequential windows must exceed 5 % of total
    /// windows, which only fires for data that is genuinely sequential.
    #[cfg(not(feature = "relaxed_entropy_validation"))]
    fn has_sequential_pattern(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        let windows = data.len() - 3;
        let threshold = if data.len() <= 64 {
            1usize
        } else {
            // 5 % of windows, minimum 4
            (windows / 20).max(4)
        };

        let mut hits = 0usize;

        for i in 0..windows {
            let ascending = data[i].wrapping_add(1) == data[i + 1] &&
                data[i + 1].wrapping_add(1) == data[i + 2] &&
                data[i + 2].wrapping_add(1) == data[i + 3];
            let descending = data[i] == data[i + 1].wrapping_add(1) &&
                data[i + 1] == data[i + 2].wrapping_add(1) &&
                data[i + 2] == data[i + 3].wrapping_add(1);
            if ascending || descending {
                hits += 1;
                if hits >= threshold {
                    return true;
                }
            }
        }

        false
    }

    /// Check if data has sufficient byte-value diversity.
    ///
    /// Counts distinct byte values and compares against a size-aware threshold.
    /// Small keys (SLH-DSA 32–128 B) need ≥40 % unique values; medium keys
    /// need ≥10 %; large keys (>10 KB) need ≥64 unique values.
    #[cfg(not(feature = "relaxed_entropy_validation"))]
    fn has_sufficient_entropy(&self, data: &[u8]) -> bool {
        if data.len() < 16 {
            return false;
        }

        let mut byte_counts = [0u32; 256];
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }

        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();

        if data.len() > 10240 {
            unique_bytes >= 64
        } else if data.len() <= 128 {
            // Small PQ keys (e.g. SLH-DSA 32–128 B): ≥40 % unique values,
            // minimum 4 unique bytes.
            unique_bytes >= (data.len() * 2 / 5).max(4)
        } else {
            // Medium keys: ≥10 % unique byte values, capped at 256 (alphabet size).
            let required = (data.len() / 10).min(256);
            unique_bytes >= required.max(1)
        }
    }

    /// Set minimum entropy requirements
    ///
    /// # Arguments
    ///
    /// * `min_entropy_bits` - Minimum entropy in bits
    pub fn set_min_entropy_bits(&mut self, min_entropy_bits: usize) {
        self.min_entropy_bits = min_entropy_bits;
    }

    /// Get minimum entropy requirements
    ///
    /// # Returns
    ///
    /// Returns the minimum entropy requirement in bits.
    pub fn min_entropy_bits(&self) -> usize {
        self.min_entropy_bits
    }

    /// Enable or disable entropy validation
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable entropy validation
    pub fn set_entropy_validation(&mut self, enabled: bool) {
        self.enable_entropy_validation = enabled;
    }

    /// Check if entropy validation is enabled
    ///
    /// # Returns
    ///
    /// Returns `true` if entropy validation is enabled, `false` otherwise.
    pub fn is_entropy_validation_enabled(&self) -> bool {
        self.enable_entropy_validation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_validator_creation() {
        let validator = EntropyValidator::new();
        assert!(
            validator.is_ok(),
            "EntropyValidator should be created successfully"
        );
    }

    #[test]
    fn test_validate_key_entropy_valid() {
        let validator = EntropyValidator::new().unwrap();

        // 32-byte key with no repeated blocks and no sequential runs.
        let high_entropy_key = vec![
            0xA3, 0x17, 0x5B, 0xE2, 0x94, 0x0D, 0x68, 0xF1, 0x3C, 0x86, 0xD5, 0x4A, 0x72, 0xBE,
            0x09, 0xC7, 0x58, 0xE4, 0x1F, 0x8B, 0xA0, 0x63, 0xD9, 0x2E, 0x7D, 0x45, 0xFB, 0x16,
            0xCA, 0x30, 0x9E, 0x54,
        ];
        let result = validator.validate_key_entropy(&high_entropy_key);
        assert!(result.is_ok(), "Should accept high-entropy key");
    }

    #[test]
    fn test_validate_key_entropy_too_short() {
        let validator = EntropyValidator::new().unwrap();

        let short_key = vec![1, 2, 3, 4];
        let result = validator.validate_key_entropy(&short_key);
        assert!(result.is_err(), "Should reject too short key");
    }

    #[test]
    fn test_validate_key_entropy_repeated_pattern() {
        let validator = EntropyValidator::new().unwrap();

        let repeated_key = vec![1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let result = validator.validate_key_entropy(&repeated_key);
        assert!(result.is_err(), "Should reject key with repeated patterns");
    }

    #[test]
    fn test_validate_key_entropy_sequential_pattern() {
        let validator = EntropyValidator::new().unwrap();

        // 16-byte key (≤64 B) — a single ascending run triggers rejection.
        let sequential_key: Vec<u8> = (1..=16).collect();
        let result = validator.validate_key_entropy(&sequential_key);
        assert!(
            result.is_err(),
            "Should reject short key that is entirely sequential"
        );
    }

    #[cfg(not(feature = "relaxed_entropy_validation"))]
    #[test]
    fn test_isolated_sequential_run_in_large_key_is_accepted() {
        let validator = EntropyValidator::new().unwrap();

        // Build a 4032-byte key (ML-DSA-65 secret key size) using a 32-bit
        // xorshift PRNG so the sequence does not cycle within 4032 bytes.
        let mut key = Vec::with_capacity(4032);
        let mut state: u32 = 0xDEAD_BEEF;
        while key.len() < 4032 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            key.extend_from_slice(&state.to_le_bytes());
        }
        key.truncate(4032);

        // Plant one ascending run at offset 100.
        key[100] = 0x50;
        key[101] = 0x51;
        key[102] = 0x52;
        key[103] = 0x53;

        let result = validator.validate_key_entropy(&key);
        assert!(
            result.is_ok(),
            "A single 4-byte ascending run in a 4032-byte key must not trigger rejection"
        );
    }

    #[cfg(not(feature = "relaxed_entropy_validation"))]
    #[test]
    fn test_massively_sequential_key_rejected() {
        let validator = EntropyValidator::new().unwrap();

        // 256-byte key that is entirely ascending (wrapping).
        let key: Vec<u8> = (0..=255).collect();
        let result = validator.validate_key_entropy(&key);
        assert!(
            result.is_err(),
            "Key that is entirely sequential should be rejected"
        );
    }

    #[test]
    fn test_entropy_validation_control() {
        let mut validator = EntropyValidator::new().unwrap();

        assert!(
            validator.is_entropy_validation_enabled(),
            "Entropy validation should be enabled by default"
        );
        assert_eq!(
            validator.min_entropy_bits(),
            128,
            "Default minimum entropy should be 128 bits"
        );

        validator.set_entropy_validation(false);
        assert!(
            !validator.is_entropy_validation_enabled(),
            "Entropy validation should be disabled"
        );

        validator.set_entropy_validation(true);
        assert!(
            validator.is_entropy_validation_enabled(),
            "Entropy validation should be enabled"
        );

        validator.set_min_entropy_bits(256);
        assert_eq!(
            validator.min_entropy_bits(),
            256,
            "Minimum entropy should be updated"
        );
    }
}
