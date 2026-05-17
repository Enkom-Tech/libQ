//! HQC Error Types
//!
//! This module defines error types for HQC operations following libQ patterns.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::string::String;

/// HQC-specific error types
///
/// This enum represents all possible errors that can occur during HQC operations.
/// Each variant includes context about when the error occurs and how to resolve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HqcError {
    /// Invalid key size
    ///
    /// **When it occurs:** A key (public or secret) has an incorrect size for the HQC parameter set.
    /// **Cause:** The key data provided doesn't match the expected size for the algorithm variant (HQC-128, HQC-192, or HQC-256).
    /// **Resolution:** Ensure the key size matches the parameter set: HQC-128 (2249 bytes public, 2289 bytes secret),
    /// HQC-192 (4522 bytes public, 4562 bytes secret), or HQC-256 (7245 bytes public, 7285 bytes secret).
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid ciphertext size
    ///
    /// **When it occurs:** A ciphertext has an incorrect size for the HQC parameter set.
    /// **Cause:** The ciphertext data doesn't match the expected size for decapsulation.
    /// **Resolution:** Ensure the ciphertext was generated for the same HQC parameter set and hasn't been corrupted.
    InvalidCiphertextSize { expected: usize, actual: usize },

    /// Invalid public key size
    ///
    /// **When it occurs:** A public key has an incorrect size.
    /// **Cause:** The public key data doesn't match the expected size for the HQC parameter set.
    /// **Resolution:** Verify the public key was generated or serialized correctly for the intended parameter set.
    InvalidPublicKeySize { expected: usize, actual: usize },

    /// Invalid secret key size
    ///
    /// **When it occurs:** A secret key has an incorrect size.
    /// **Cause:** The secret key data doesn't match the expected size for the HQC parameter set.
    /// **Resolution:** Verify the secret key was generated or deserialized correctly for the intended parameter set.
    InvalidSecretKeySize { expected: usize, actual: usize },

    /// Decryption failed
    ///
    /// **When it occurs:** Decapsulation fails to recover the shared secret.
    /// **Cause:** The ciphertext may be corrupted, the secret key may be incorrect, or the ciphertext was generated with a different public key.
    /// **Resolution:** Verify the ciphertext and secret key are valid and correspond to each other.
    DecryptionFailed,

    /// Invalid size
    ///
    /// **When it occurs:** A size parameter is invalid or out of bounds.
    /// **Cause:** A size value doesn't meet the requirements for the operation.
    /// **Resolution:** Check that all size parameters are within valid ranges for the HQC parameter set.
    InvalidSize,

    /// Encryption failed
    ///
    /// **When it occurs:** Encapsulation fails to generate a valid ciphertext.
    /// **Cause:** Random number generation may have failed, or internal computation encountered an error.
    /// **Resolution:** Ensure a secure random number generator is available and functioning correctly.
    EncryptionFailed,

    /// Key generation failed
    ///
    /// **When it occurs:** Key pair generation fails.
    /// **Cause:** Random number generation may have failed, or internal computation encountered an error.
    /// **Resolution:** Ensure a secure random number generator is available and functioning correctly.
    KeyGenerationFailed,

    /// Random number generation failed
    ///
    /// **When it occurs:** The random number generator fails to produce random bytes.
    /// **Cause:** The underlying RNG implementation encountered an error or is unavailable.
    /// **Resolution:** Check RNG initialization and ensure a secure random source is available.
    RandomGenerationFailed,

    /// Internal error
    ///
    /// **When it occurs:** An unexpected internal error occurs during HQC operations.
    /// **Cause:** This typically indicates a bug in the implementation or corrupted internal state.
    /// **Resolution:** Report this error as it may indicate a software bug. Check inputs and system state.
    InternalError,

    /// Not implemented
    ///
    /// **When it occurs:** A requested feature or operation is not yet implemented.
    /// **Cause:** The operation is not available in the current implementation.
    /// **Resolution:** Check if an alternative approach is available, or wait for the feature to be implemented.
    NotImplemented,

    /// Invalid parameter
    ///
    /// **When it occurs:** A parameter value is invalid for the operation.
    /// **Cause:** A parameter doesn't meet the requirements or constraints for the HQC operation.
    /// **Resolution:** Verify all parameters are within valid ranges and meet the algorithm requirements.
    InvalidParameter,

    /// Memory allocation failed
    ///
    /// **When it occurs:** Dynamic memory allocation fails during an operation.
    /// **Cause:** Insufficient memory is available, or allocation is not supported in the current environment.
    /// **Resolution:** Ensure sufficient memory is available, or use a no_std-compatible configuration.
    AllocationFailed,

    /// Hash function error
    ///
    /// **When it occurs:** A hash function operation fails.
    /// **Cause:** The underlying hash implementation encountered an error.
    /// **Resolution:** Check that the hash function implementation is properly initialized and functioning.
    HashError,

    /// BCH code error
    ///
    /// **When it occurs:** BCH (Bose-Chaudhuri-Hocquenghem) code operations fail.
    /// **Cause:** Error correction code computation encountered an error, possibly due to corrupted data.
    /// **Resolution:** Verify input data integrity and that error correction parameters are correct.
    BchError,

    /// Polynomial operation error
    ///
    /// **When it occurs:** Polynomial arithmetic operations fail.
    /// **Cause:** Polynomial computation encountered an error, possibly due to invalid coefficients or degree.
    /// **Resolution:** Verify polynomial inputs are valid and within expected ranges.
    PolynomialError,

    /// Encoding error
    ///
    /// **When it occurs:** Encoding operations fail.
    /// **Cause:** Data encoding encountered an error, possibly due to invalid input format.
    /// **Resolution:** Verify input data format and encoding parameters are correct.
    EncodingError,

    /// Verification error
    ///
    /// **When it occurs:** Verification operations fail.
    /// **Cause:** Data verification failed, indicating the data may be corrupted or invalid.
    /// **Resolution:** Verify input data integrity and that verification parameters are correct.
    VerificationError,

    /// Invalid weight
    ///
    /// **When it occurs:** A polynomial weight is invalid for the operation.
    /// **Cause:** The weight parameter doesn't meet the requirements for the HQC parameter set.
    /// **Resolution:** Ensure the weight is within valid ranges: HQC-128 (66), HQC-192 (103), or HQC-256 (134).
    InvalidWeight,

    /// Allocation required (for no_std environments)
    ///
    /// **When it occurs:** An operation requires dynamic allocation but the `alloc` feature is not enabled.
    /// **Cause:** The operation needs heap allocation but the crate is compiled in `no_std` mode without `alloc`.
    /// **Resolution:** Enable the `alloc` feature or use an alternative approach that doesn't require allocation.
    AllocRequired,
}

impl fmt::Display for HqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HqcError::InvalidKeySize { expected, actual } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, actual)
            }
            HqcError::InvalidCiphertextSize { expected, actual } => {
                write!(
                    f,
                    "Invalid ciphertext size: expected {}, got {}",
                    expected, actual
                )
            }
            HqcError::InvalidPublicKeySize { expected, actual } => {
                write!(
                    f,
                    "Invalid public key size: expected {}, got {}",
                    expected, actual
                )
            }
            HqcError::InvalidSecretKeySize { expected, actual } => {
                write!(
                    f,
                    "Invalid secret key size: expected {}, got {}",
                    expected, actual
                )
            }
            HqcError::DecryptionFailed => write!(f, "Decryption failed"),
            HqcError::InvalidSize => write!(f, "Invalid size"),
            HqcError::EncryptionFailed => write!(f, "Encryption failed"),
            HqcError::KeyGenerationFailed => write!(f, "Key generation failed"),
            HqcError::RandomGenerationFailed => write!(f, "Random number generation failed"),
            HqcError::InternalError => write!(f, "Internal error"),
            HqcError::NotImplemented => write!(f, "Not implemented"),
            HqcError::InvalidParameter => write!(f, "Invalid parameter"),
            HqcError::AllocationFailed => write!(f, "Memory allocation failed"),
            HqcError::HashError => write!(f, "Hash function error"),
            HqcError::BchError => write!(f, "BCH code error"),
            HqcError::PolynomialError => write!(f, "Polynomial operation error"),
            HqcError::EncodingError => write!(f, "Encoding error"),
            HqcError::VerificationError => write!(f, "Verification error"),
            HqcError::InvalidWeight => write!(f, "Invalid weight"),
            HqcError::AllocRequired => write!(f, "Allocation required (no_std environment)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HqcError {}

impl From<HqcError> for lib_q_core::Error {
    fn from(err: HqcError) -> Self {
        match err {
            HqcError::InvalidKeySize { expected, actual } => {
                lib_q_core::Error::InvalidKeySize { expected, actual }
            }
            HqcError::InvalidCiphertextSize { expected, actual } => {
                lib_q_core::Error::InvalidCiphertextSize { expected, actual }
            }
            HqcError::InvalidPublicKeySize { expected, actual } => {
                // Map to InvalidKeySize since InvalidPublicKeySize doesn't exist in lib-q-core
                lib_q_core::Error::InvalidKeySize { expected, actual }
            }
            HqcError::InvalidSecretKeySize { expected, actual } => {
                // Map to InvalidKeySize since InvalidSecretKeySize doesn't exist in lib-q-core
                lib_q_core::Error::InvalidKeySize { expected, actual }
            }
            HqcError::DecryptionFailed => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::DecryptionFailed {
                        operation: String::from("HQC decapsulation"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::DecryptionFailed {
                        operation: "HQC decapsulation".into(),
                    }
                }
            }
            HqcError::InvalidSize => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC operation"),
                        details: String::from("Invalid size parameter"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC operation".into(),
                        details: "Invalid size parameter".into(),
                    }
                }
            }
            HqcError::EncryptionFailed => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::EncryptionFailed {
                        operation: String::from("HQC encapsulation"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::EncryptionFailed {
                        operation: "HQC encapsulation".into(),
                    }
                }
            }
            HqcError::KeyGenerationFailed => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::KeyGenerationFailed {
                        operation: String::from("HQC key generation"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::KeyGenerationFailed {
                        operation: "HQC key generation".into(),
                    }
                }
            }
            HqcError::RandomGenerationFailed => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::RandomGenerationFailed {
                        operation: String::from("HQC random generation"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::RandomGenerationFailed {
                        operation: "HQC random generation".into(),
                    }
                }
            }
            HqcError::InternalError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC operation"),
                        details: String::from("Internal error"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC operation".into(),
                        details: "Internal error".into(),
                    }
                }
            }
            HqcError::NotImplemented => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::NotImplemented {
                        feature: String::from("HQC feature"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::NotImplemented {
                        feature: "HQC feature".into(),
                    }
                }
            }
            HqcError::InvalidParameter => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC operation"),
                        details: String::from("Invalid parameter"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC operation".into(),
                        details: "Invalid parameter".into(),
                    }
                }
            }
            HqcError::AllocationFailed => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::MemoryAllocationFailed {
                        operation: String::from("HQC operation"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::MemoryAllocationFailed {
                        operation: "HQC operation".into(),
                    }
                }
            }
            HqcError::HashError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC hash operation"),
                        details: String::from("Hash computation failed"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC hash operation".into(),
                        details: "Hash computation failed".into(),
                    }
                }
            }
            HqcError::BchError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC BCH operation"),
                        details: String::from("BCH code error"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC BCH operation".into(),
                        details: "BCH code error".into(),
                    }
                }
            }
            HqcError::PolynomialError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC polynomial operation"),
                        details: String::from("Polynomial computation error"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC polynomial operation".into(),
                        details: "Polynomial computation error".into(),
                    }
                }
            }
            HqcError::EncodingError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC encoding operation"),
                        details: String::from("Encoding computation error"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC encoding operation".into(),
                        details: "Encoding computation error".into(),
                    }
                }
            }
            HqcError::VerificationError => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC verification operation"),
                        details: String::from("Verification computation error"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC verification operation".into(),
                        details: "Verification computation error".into(),
                    }
                }
            }
            HqcError::InvalidWeight => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC weight validation"),
                        details: String::from("Invalid polynomial weight"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC weight validation".into(),
                        details: "Invalid polynomial weight".into(),
                    }
                }
            }
            HqcError::AllocRequired => {
                #[cfg(feature = "alloc")]
                {
                    lib_q_core::Error::InternalError {
                        operation: String::from("HQC operation"),
                        details: String::from("Allocation required but not available"),
                    }
                }
                #[cfg(not(feature = "alloc"))]
                {
                    lib_q_core::Error::InternalError {
                        operation: "HQC operation".into(),
                        details: "Allocation required but not available".into(),
                    }
                }
            }
        }
    }
}

impl From<lib_q_core::Error> for HqcError {
    fn from(err: lib_q_core::Error) -> Self {
        match err {
            lib_q_core::Error::InvalidKeySize { expected, actual } => {
                HqcError::InvalidKeySize { expected, actual }
            }
            lib_q_core::Error::InvalidCiphertextSize { expected, actual } => {
                HqcError::InvalidCiphertextSize { expected, actual }
            }
            // Note: InvalidPublicKeySize and InvalidSecretKeySize don't exist in lib-q-core
            // They are mapped to InvalidKeySize in the forward direction
            lib_q_core::Error::DecryptionFailed { .. } => HqcError::DecryptionFailed,
            lib_q_core::Error::EncryptionFailed { .. } => HqcError::EncryptionFailed,
            lib_q_core::Error::KeyGenerationFailed { .. } => HqcError::KeyGenerationFailed,
            lib_q_core::Error::RandomGenerationFailed { .. } => HqcError::RandomGenerationFailed,
            lib_q_core::Error::InternalError { .. } => HqcError::InternalError,
            lib_q_core::Error::NotImplemented { .. } => HqcError::NotImplemented,
            lib_q_core::Error::MemoryAllocationFailed { .. } => HqcError::AllocationFailed,
            _ => HqcError::InternalError, // Map unknown errors to internal error
        }
    }
}
