//! Security constants for lib-Q
//!
//! This module provides security-related constants used throughout the library
//! for validation and configuration.

use lib_q_types::{
    cbkem,
    fndsa,
    hqc,
    mldsa,
    mlkem,
    slhdsa,
};

use crate::api::Algorithm;
use crate::error::Result;

/// Security constants for lib-Q
///
/// This struct provides access to security-related constants used throughout
/// the library for validation and configuration.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct SecurityConstants {
    /// Maximum plaintext, ciphertext, or associated-data size for a single AEAD operation.
    ///
    /// A modest default encourages chunking and reduces accidental nonce reuse under streaming
    /// misuse; raise via [`Self::set_max_aead_message_size`] when your deployment accepts larger
    /// single-shot bindings.
    max_aead_message_size: usize,
    /// Maximum input length for hash absorb and for signature message preimages.
    ///
    /// Defaults to [`usize::MAX`] so digest and sign APIs are not capped by the AEAD binding
    /// policy. Lower this in environments that need a hard resource ceiling on preimage size.
    max_hash_message_size: usize,
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
            max_aead_message_size: 1024 * 1024, // 1 MiB
            max_hash_message_size: usize::MAX,
            standard_nonce_size: 16, // 16 bytes
            min_randomness_size: 32, // 32 bytes
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
    /// Maximum plaintext, ciphertext, or AAD size for one AEAD call.
    pub fn max_aead_message_size(&self) -> usize {
        self.max_aead_message_size
    }

    /// Maximum hash input length and signature message length.
    pub fn max_hash_message_size(&self) -> usize {
        self.max_hash_message_size
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
                    mlkem::MLKEM512_SECRET_KEY_BYTES
                } else {
                    mlkem::MLKEM512_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::MlKem768 => {
                if is_secret {
                    mlkem::MLKEM768_SECRET_KEY_BYTES
                } else {
                    mlkem::MLKEM768_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::MlKem1024 => {
                if is_secret {
                    mlkem::MLKEM1024_SECRET_KEY_BYTES
                } else {
                    mlkem::MLKEM1024_PUBLIC_KEY_BYTES
                }
            }
            // CB-KEM algorithms — sizes from `lib_q_types::cbkem`.
            Algorithm::CbKem348864 => {
                if is_secret {
                    cbkem::CBKEM348864_SECRET_KEY_BYTES
                } else {
                    cbkem::CBKEM348864_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::CbKem460896 => {
                if is_secret {
                    cbkem::CBKEM460896_SECRET_KEY_BYTES
                } else {
                    cbkem::CBKEM460896_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::CbKem6688128 => {
                if is_secret {
                    cbkem::CBKEM6688128_SECRET_KEY_BYTES
                } else {
                    cbkem::CBKEM6688128_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::CbKem6960119 => {
                if is_secret {
                    cbkem::CBKEM6960119_SECRET_KEY_BYTES
                } else {
                    cbkem::CBKEM6960119_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::CbKem8192128 => {
                if is_secret {
                    cbkem::CBKEM8192128_SECRET_KEY_BYTES
                } else {
                    cbkem::CBKEM8192128_PUBLIC_KEY_BYTES
                }
            }

            // HQC KEM — sizes from `lib_q_types::hqc` (single source of truth).
            Algorithm::Hqc128 => {
                if is_secret {
                    hqc::HQC128_SECRET_KEY_BYTES
                } else {
                    hqc::HQC128_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::Hqc192 => {
                if is_secret {
                    hqc::HQC192_SECRET_KEY_BYTES
                } else {
                    hqc::HQC192_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::Hqc256 => {
                if is_secret {
                    hqc::HQC256_SECRET_KEY_BYTES
                } else {
                    hqc::HQC256_PUBLIC_KEY_BYTES
                }
            }

            // Signature algorithms — sizes from `lib_q_types::mldsa`.
            Algorithm::MlDsa44 => {
                if is_secret {
                    mldsa::MLDSA44_SECRET_KEY_BYTES
                } else {
                    mldsa::MLDSA44_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::MlDsa65 => {
                if is_secret {
                    mldsa::MLDSA65_SECRET_KEY_BYTES
                } else {
                    mldsa::MLDSA65_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::MlDsa87 => {
                if is_secret {
                    mldsa::MLDSA87_SECRET_KEY_BYTES
                } else {
                    mldsa::MLDSA87_PUBLIC_KEY_BYTES
                }
            }
            // FN-DSA — sizes from `lib_q_types::fndsa`, which derives them at compile time from
            // `lib-q-fn-dsa-comm`'s own `sign_key_size`/`vrfy_key_size` `const fn`s (genuinely
            // derived, not a hand-copied literal). This is the exact table that once read 2561
            // instead of 2305 for FN-DSA-1024's secret key, which made
            // `LibQSignatureProvider` reject every FN-DSA-1024 key the library generated.
            Algorithm::FnDsa | Algorithm::FnDsa512 => {
                if is_secret {
                    fndsa::FNDSA512_SECRET_KEY_BYTES
                } else {
                    fndsa::FNDSA512_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::FnDsa1024 => {
                if is_secret {
                    fndsa::FNDSA1024_SECRET_KEY_BYTES
                } else {
                    fndsa::FNDSA1024_PUBLIC_KEY_BYTES
                }
            }

            // SLH-DSA algorithms — sizes from `lib_q_types::slhdsa`.
            Algorithm::SlhDsaSha256128fRobust | Algorithm::SlhDsaShake256128fRobust => {
                if is_secret {
                    slhdsa::SLHDSA_128F_SECRET_KEY_BYTES
                } else {
                    slhdsa::SLHDSA_128F_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::SlhDsaSha256192fRobust | Algorithm::SlhDsaShake256192fRobust => {
                if is_secret {
                    slhdsa::SLHDSA_192F_SECRET_KEY_BYTES
                } else {
                    slhdsa::SLHDSA_192F_PUBLIC_KEY_BYTES
                }
            }
            Algorithm::SlhDsaSha256256fRobust | Algorithm::SlhDsaShake256256fRobust => {
                if is_secret {
                    slhdsa::SLHDSA_256F_SECRET_KEY_BYTES
                } else {
                    slhdsa::SLHDSA_256F_PUBLIC_KEY_BYTES
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
            Algorithm::MlKem512 => mlkem::MLKEM512_CIPHERTEXT_BYTES,
            Algorithm::MlKem768 => mlkem::MLKEM768_CIPHERTEXT_BYTES,
            Algorithm::MlKem1024 => mlkem::MLKEM1024_CIPHERTEXT_BYTES,

            // CB-KEM algorithms — sizes from `lib_q_types::cbkem`.
            Algorithm::CbKem348864 => cbkem::CBKEM348864_CIPHERTEXT_BYTES,
            Algorithm::CbKem460896 => cbkem::CBKEM460896_CIPHERTEXT_BYTES,
            Algorithm::CbKem6688128 => cbkem::CBKEM6688128_CIPHERTEXT_BYTES,
            Algorithm::CbKem6960119 => cbkem::CBKEM6960119_CIPHERTEXT_BYTES,
            Algorithm::CbKem8192128 => cbkem::CBKEM8192128_CIPHERTEXT_BYTES,

            Algorithm::Hqc128 => hqc::HQC128_CIPHERTEXT_BYTES,
            Algorithm::Hqc192 => hqc::HQC192_CIPHERTEXT_BYTES,
            Algorithm::Hqc256 => hqc::HQC256_CIPHERTEXT_BYTES,

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
            Algorithm::MlDsa44 => mldsa::MLDSA44_SIGNATURE_BYTES,
            Algorithm::MlDsa65 => mldsa::MLDSA65_SIGNATURE_BYTES,
            Algorithm::MlDsa87 => mldsa::MLDSA87_SIGNATURE_BYTES,
            Algorithm::FnDsa | Algorithm::FnDsa512 => fndsa::FNDSA512_SIGNATURE_BYTES,
            Algorithm::FnDsa1024 => fndsa::FNDSA1024_SIGNATURE_BYTES,

            // SLH-DSA signature sizes — from `lib_q_types::slhdsa`.
            Algorithm::SlhDsaSha256128fRobust | Algorithm::SlhDsaShake256128fRobust => {
                slhdsa::SLHDSA_128F_SIGNATURE_BYTES
            }
            Algorithm::SlhDsaSha256192fRobust | Algorithm::SlhDsaShake256192fRobust => {
                slhdsa::SLHDSA_192F_SIGNATURE_BYTES
            }
            Algorithm::SlhDsaSha256256fRobust | Algorithm::SlhDsaShake256256fRobust => {
                slhdsa::SLHDSA_256F_SIGNATURE_BYTES
            }

            _ => {
                return Err(crate::error::Error::InvalidAlgorithm {
                    algorithm: "Algorithm does not produce signatures",
                });
            }
        };

        Ok(expected_size)
    }

    /// Set the maximum AEAD plaintext, ciphertext, or AAD size (bytes) for one operation.
    pub fn set_max_aead_message_size(&mut self, max_size: usize) {
        self.max_aead_message_size = max_size;
    }

    /// Set the maximum hash input and signature message size (bytes).
    pub fn set_max_hash_message_size(&mut self, max_size: usize) {
        self.max_hash_message_size = max_size;
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
    use lib_q_types::hqc;

    use super::*;

    #[test]
    fn test_security_constants_creation() {
        let constants = SecurityConstants::new();
        assert_eq!(constants.max_aead_message_size(), 1024 * 1024);
        assert_eq!(constants.max_hash_message_size(), usize::MAX);
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

        assert_eq!(
            constants
                .get_expected_key_size(Algorithm::Hqc128, false)
                .unwrap(),
            hqc::HQC128_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            constants
                .get_expected_key_size(Algorithm::Hqc128, true)
                .unwrap(),
            hqc::HQC128_SECRET_KEY_BYTES
        );

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

        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::Hqc128)
                .unwrap(),
            hqc::HQC128_CIPHERTEXT_BYTES
        );
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::Hqc192)
                .unwrap(),
            hqc::HQC192_CIPHERTEXT_BYTES
        );
        assert_eq!(
            constants
                .get_expected_ciphertext_size(Algorithm::Hqc256)
                .unwrap(),
            hqc::HQC256_CIPHERTEXT_BYTES
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

        constants.set_max_aead_message_size(2048 * 1024);
        assert_eq!(constants.max_aead_message_size(), 2048 * 1024);

        constants.set_max_hash_message_size(4096);
        assert_eq!(constants.max_hash_message_size(), 4096);

        // Test setting nonce size
        constants.set_standard_nonce_size(32);
        assert_eq!(constants.standard_nonce_size(), 32);

        // Test setting minimum randomness size
        constants.set_min_randomness_size(64);
        assert_eq!(constants.min_randomness_size(), 64);
    }
}
