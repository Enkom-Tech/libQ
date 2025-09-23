//! Security constants for lib-Q
//!
//! This module provides security-related constants used throughout the library
//! for validation and configuration.

use crate::api::Algorithm;
use crate::error::Result;

/// Security constants for lib-Q
///
/// This struct provides access to security-related constants used throughout
/// the library for validation and configuration.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct SecurityConstants {
    // Maximum message size in bytes (1MB)
    max_message_size: usize,
    // Standard nonce size in bytes (16 bytes)
    standard_nonce_size: usize,
    // Minimum randomness size in bytes (32 bytes)
    min_randomness_size: usize,
}

#[cfg(feature = "alloc")]
impl SecurityConstants {
    /// Create a new SecurityConstants instance
    ///
    /// # Returns
    ///
    /// A new instance of SecurityConstants with default values.
    pub fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            standard_nonce_size: 16,       // 16 bytes
            min_randomness_size: 32,       // 32 bytes
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for SecurityConstants {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityConstants {
    /// Get the maximum message size
    ///
    /// # Returns
    ///
    /// Returns the maximum allowed message size in bytes.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Get the standard nonce size
    ///
    /// # Returns
    ///
    /// Returns the standard nonce size in bytes.
    pub fn standard_nonce_size(&self) -> usize {
        self.standard_nonce_size
    }

    /// Get the minimum randomness size
    ///
    /// # Returns
    ///
    /// Returns the minimum required randomness size in bytes.
    pub fn min_randomness_size(&self) -> usize {
        self.min_randomness_size
    }

    /// Get the expected key size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to get the key size for
    /// * `is_secret` - Whether this is a secret key (affects expected size)
    ///
    /// # Returns
    ///
    /// Returns the expected key size in bytes, or an error if the algorithm
    /// doesn't use keys or is not supported.
    pub fn get_expected_key_size(&self, algorithm: Algorithm, is_secret: bool) -> Result<usize> {
        let expected_size = match algorithm {
            // KEM algorithms
            Algorithm::MlKem512 => {
                if is_secret {
                    1632
                } else {
                    800
                }
            }
            Algorithm::MlKem768 => {
                if is_secret {
                    2400
                } else {
                    1184
                }
            }
            Algorithm::MlKem1024 => {
                if is_secret {
                    3168
                } else {
                    1568
                }
            }
            Algorithm::Dawn => 1024,

            // Signature algorithms
            Algorithm::MlDsa44 => {
                if is_secret {
                    2560 // ML-DSA-44 secret key size
                } else {
                    1312 // ML-DSA-44 public key size
                }
            }
            Algorithm::MlDsa65 => {
                if is_secret {
                    4032 // ML-DSA-65 secret key size
                } else {
                    1952 // ML-DSA-65 public key size
                }
            }
            Algorithm::MlDsa87 => {
                if is_secret {
                    4896 // ML-DSA-87 secret key size
                } else {
                    2592 // ML-DSA-87 public key size
                }
            }
            Algorithm::FnDsa => {
                if is_secret {
                    1281 // FN-DSA-512 secret key size (logn=9)
                } else {
                    897 // FN-DSA-512 public key size (logn=9)
                }
            }
            Algorithm::FnDsa512 => {
                if is_secret {
                    1281 // FN-DSA-512 secret key size (logn=9)
                } else {
                    897 // FN-DSA-512 public key size (logn=9)
                }
            }
            Algorithm::FnDsa1024 => {
                if is_secret {
                    2561 // FN-DSA-1024 secret key size (logn=10)
                } else {
                    1793 // FN-DSA-1024 public key size (logn=10)
                }
            }

            // SLH-DSA algorithms
            Algorithm::SlhDsaSha256128fRobust => {
                if is_secret {
                    64 // SLH-DSA SHA256-128f secret key size (4 * N where N=16)
                } else {
                    32 // SLH-DSA SHA256-128f public key size (2 * N where N=16)
                }
            }
            Algorithm::SlhDsaSha256192fRobust => {
                if is_secret {
                    96 // SLH-DSA SHA256-192f secret key size (4 * N where N=24)
                } else {
                    48 // SLH-DSA SHA256-192f public key size (2 * N where N=24)
                }
            }
            Algorithm::SlhDsaSha256256fRobust => {
                if is_secret {
                    128 // SLH-DSA SHA256-256f secret key size (4 * N where N=32)
                } else {
                    64 // SLH-DSA SHA256-256f public key size (2 * N where N=32)
                }
            }
            Algorithm::SlhDsaShake256128fRobust => {
                if is_secret {
                    64 // SLH-DSA SHAKE256-128f secret key size (4 * N where N=16)
                } else {
                    32 // SLH-DSA SHAKE256-128f public key size (2 * N where N=16)
                }
            }
            Algorithm::SlhDsaShake256192fRobust => {
                if is_secret {
                    96 // SLH-DSA SHAKE256-192f secret key size (4 * N where N=24)
                } else {
                    48 // SLH-DSA SHAKE256-192f public key size (2 * N where N=24)
                }
            }
            Algorithm::SlhDsaShake256256fRobust => {
                if is_secret {
                    128 // SLH-DSA SHAKE256-256f secret key size (4 * N where N=32)
                } else {
                    64 // SLH-DSA SHAKE256-256f public key size (2 * N where N=32)
                }
            }

            // Hash algorithms don't have keys
            _ => {
                return Err(crate::error::Error::InvalidAlgorithm {
                    algorithm: "Algorithm does not use keys",
                });
            }
        };

        Ok(expected_size)
    }

    /// Get the expected ciphertext size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to get the ciphertext size for
    ///
    /// # Returns
    ///
    /// Returns the expected ciphertext size in bytes, or an error if the algorithm
    /// doesn't produce ciphertext or is not supported.
    pub fn get_expected_ciphertext_size(&self, algorithm: Algorithm) -> Result<usize> {
        let expected_size = match algorithm {
            Algorithm::MlKem512 => 768,   // ML-KEM-512 ciphertext size
            Algorithm::MlKem768 => 1088,  // ML-KEM-768 ciphertext size
            Algorithm::MlKem1024 => 1568, // ML-KEM-1024 ciphertext size
            Algorithm::Dawn => 1024,      // DAWN ciphertext size
            _ => {
                return Err(crate::error::Error::InvalidAlgorithm {
                    algorithm: "Algorithm does not produce ciphertext",
                });
            }
        };

        Ok(expected_size)
    }

    /// Get the expected signature size for a given algorithm
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm to get the signature size for
    ///
    /// # Returns
    ///
    /// Returns the expected signature size in bytes, or an error if the algorithm
    /// doesn't produce signatures or is not supported.
    pub fn get_expected_signature_size(&self, algorithm: Algorithm) -> Result<usize> {
        let expected_size = match algorithm {
            Algorithm::MlDsa44 => 2420,   // ML-DSA-44 signature size
            Algorithm::MlDsa65 => 3309,   // ML-DSA-65 signature size
            Algorithm::MlDsa87 => 4627,   // ML-DSA-87 signature size
            Algorithm::FnDsa => 666,      // FN-DSA-512 signature size (logn=9)
            Algorithm::FnDsa512 => 666,   // FN-DSA-512 signature size (logn=9)
            Algorithm::FnDsa1024 => 1280, // FN-DSA-1024 signature size (logn=10)

            // SLH-DSA signature sizes (actual sizes from implementation)
            Algorithm::SlhDsaSha256128fRobust => 17088, // SLH-DSA SHA256-128f signature size
            Algorithm::SlhDsaSha256192fRobust => 35664, // SLH-DSA SHA256-192f signature size
            Algorithm::SlhDsaSha256256fRobust => 49856, // SLH-DSA SHA256-256f signature size
            Algorithm::SlhDsaShake256128fRobust => 17088, // SLH-DSA SHAKE256-128f signature size
            Algorithm::SlhDsaShake256192fRobust => 35664, // SLH-DSA SHAKE256-192f signature size
            Algorithm::SlhDsaShake256256fRobust => 49856, // SLH-DSA SHAKE256-256f signature size

            _ => {
                return Err(crate::error::Error::InvalidAlgorithm {
                    algorithm: "Algorithm does not produce signatures",
                });
            }
        };

        Ok(expected_size)
    }

    /// Set the maximum message size
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum message size in bytes
    pub fn set_max_message_size(&mut self, max_size: usize) {
        self.max_message_size = max_size;
    }

    /// Set the standard nonce size
    ///
    /// # Arguments
    ///
    /// * `nonce_size` - The standard nonce size in bytes
    pub fn set_standard_nonce_size(&mut self, nonce_size: usize) {
        self.standard_nonce_size = nonce_size;
    }

    /// Set the minimum randomness size
    ///
    /// # Arguments
    ///
    /// * `min_size` - The minimum randomness size in bytes
    pub fn set_min_randomness_size(&mut self, min_size: usize) {
        self.min_randomness_size = min_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_constants_creation() {
        let constants = SecurityConstants::new();
        assert_eq!(constants.max_message_size(), 1024 * 1024);
        assert_eq!(constants.standard_nonce_size(), 16);
        assert_eq!(constants.min_randomness_size(), 32);
    }

    #[test]
    fn test_get_expected_key_size() {
        let constants = SecurityConstants::new();

        // Test ML-KEM-512
        let public_size = constants
            .get_expected_key_size(Algorithm::MlKem512, false)
            .unwrap();
        assert_eq!(public_size, 800);

        let secret_size = constants
            .get_expected_key_size(Algorithm::MlKem512, true)
            .unwrap();
        assert_eq!(secret_size, 1632);

        // Test ML-DSA-65
        let public_size = constants
            .get_expected_key_size(Algorithm::MlDsa65, false)
            .unwrap();
        assert_eq!(public_size, 1952);

        let secret_size = constants
            .get_expected_key_size(Algorithm::MlDsa65, true)
            .unwrap();
        assert_eq!(secret_size, 4032);

        // Test hash algorithm (should fail)
        let result = constants.get_expected_key_size(Algorithm::Sha3_256, false);
        assert!(result.is_err(), "Hash algorithms should not have keys");
    }

    #[test]
    fn test_get_expected_ciphertext_size() {
        let constants = SecurityConstants::new();

        // Test ML-KEM algorithms
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::MlKem512)
                .unwrap(),
            768
        );
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::MlKem768)
                .unwrap(),
            1088
        );
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::MlKem1024)
                .unwrap(),
            1568
        );

        // Test other KEM algorithms
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::Dawn)
                .unwrap(),
            1024
        );

        // Test non-KEM algorithm (should fail)
        let result = constants.get_expected_ciphertext_size(Algorithm::Sha3_256);
        assert!(
            result.is_err(),
            "Non-KEM algorithms should not produce ciphertext"
        );
    }

    #[test]
    fn test_get_expected_signature_size() {
        let constants = SecurityConstants::new();

        // Test ML-DSA algorithms
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::MlDsa44)
                .unwrap(),
            2420
        );
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::MlDsa65)
                .unwrap(),
            3309
        );
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::MlDsa87)
                .unwrap(),
            4627
        );

        // Test FN-DSA algorithms
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::FnDsa)
                .unwrap(),
            666
        );
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::FnDsa512)
                .unwrap(),
            666
        );
        assert_eq!(
            constants
                .get_expected_signature_size(Algorithm::FnDsa1024)
                .unwrap(),
            1280
        );

        // Test non-signature algorithm (should fail)
        let result = constants.get_expected_signature_size(Algorithm::Sha3_256);
        assert!(
            result.is_err(),
            "Non-signature algorithms should not produce signatures"
        );
    }

    #[test]
    fn test_set_constants() {
        let mut constants = SecurityConstants::new();

        // Test setting max message size
        constants.set_max_message_size(2048 * 1024);
        assert_eq!(constants.max_message_size(), 2048 * 1024);

        // Test setting nonce size
        constants.set_standard_nonce_size(32);
        assert_eq!(constants.standard_nonce_size(), 32);

        // Test setting minimum randomness size
        constants.set_min_randomness_size(64);
        assert_eq!(constants.min_randomness_size(), 64);
    }
}
