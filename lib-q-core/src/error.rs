//! Error handling for lib-Q
//!
//! This module defines the error types used throughout the library.

use core::fmt;

/// The error type for lib-Q operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid key size
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid signature size
    InvalidSignatureSize { expected: usize, actual: usize },

    /// Invalid nonce size
    InvalidNonceSize { expected: usize, actual: usize },

    /// Invalid message size
    InvalidMessageSize { max: usize, actual: usize },

    /// Invalid ciphertext size
    InvalidCiphertextSize { expected: usize, actual: usize },

    /// Invalid plaintext size
    InvalidPlaintextSize { expected: usize, actual: usize },

    /// Invalid hash size
    InvalidHashSize { expected: usize, actual: usize },

    /// Invalid algorithm
    InvalidAlgorithm { algorithm: String },

    /// Invalid security level
    InvalidSecurityLevel {
        level: u32,
        supported: &'static [u32],
    },

    /// Verification failed
    VerificationFailed { operation: String },

    /// Encryption failed
    EncryptionFailed { operation: String },

    /// Decryption failed
    DecryptionFailed { operation: String },

    /// Key generation failed
    KeyGenerationFailed { operation: String },

    /// Random number generation failed
    RandomGenerationFailed { operation: String },

    /// Memory allocation failed
    MemoryAllocationFailed { operation: String },

    /// Internal error
    InternalError { operation: String, details: String },

    /// Not implemented
    NotImplemented { feature: String },

    /// Unsupported operation
    UnsupportedOperation { operation: String },

    /// Invalid state
    InvalidState { operation: String, reason: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeySize { expected, actual } => {
                write!(f, "Invalid key size: expected {expected}, got {actual}")
            }
            Error::InvalidSignatureSize { expected, actual } => {
                write!(
                    f,
                    "Invalid signature size: expected {expected}, got {actual}"
                )
            }
            Error::InvalidNonceSize { expected, actual } => {
                write!(f, "Invalid nonce size: expected {expected}, got {actual}")
            }
            Error::InvalidMessageSize { max, actual } => {
                write!(f, "Invalid message size: maximum {max}, got {actual}")
            }
            Error::InvalidCiphertextSize { expected, actual } => {
                write!(
                    f,
                    "Invalid ciphertext size: expected {expected}, got {actual}"
                )
            }
            Error::InvalidPlaintextSize { expected, actual } => {
                write!(
                    f,
                    "Invalid plaintext size: expected {expected}, got {actual}"
                )
            }
            Error::InvalidHashSize { expected, actual } => {
                write!(f, "Invalid hash size: expected {expected}, got {actual}")
            }
            Error::InvalidAlgorithm { algorithm } => {
                write!(f, "Invalid algorithm: {algorithm}")
            }
            Error::InvalidSecurityLevel { level, supported } => {
                write!(
                    f,
                    "Invalid security level: {level} (supported: {supported:?})"
                )
            }
            Error::VerificationFailed { operation } => {
                write!(f, "Verification failed: {operation}")
            }
            Error::EncryptionFailed { operation } => {
                write!(f, "Encryption failed: {operation}")
            }
            Error::DecryptionFailed { operation } => {
                write!(f, "Decryption failed: {operation}")
            }
            Error::KeyGenerationFailed { operation } => {
                write!(f, "Key generation failed: {operation}")
            }
            Error::RandomGenerationFailed { operation } => {
                write!(f, "Random generation failed: {operation}")
            }
            Error::MemoryAllocationFailed { operation } => {
                write!(f, "Memory allocation failed: {operation}")
            }
            Error::InternalError { operation, details } => {
                write!(f, "Internal error in {operation}: {details}")
            }
            Error::NotImplemented { feature } => {
                write!(f, "Feature not implemented: {feature}")
            }
            Error::UnsupportedOperation { operation } => {
                write!(f, "Unsupported operation: {operation}")
            }
            Error::InvalidState { operation, reason } => {
                write!(f, "Invalid state in {operation}: {reason}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for lib-Q operations
pub type Result<T> = core::result::Result<T, Error>;

/// Security levels supported by lib-Q
pub const SECURITY_LEVELS: &[u32] = &[1, 3, 4, 5];

/// Check if a security level is supported
pub fn is_supported_security_level(level: u32) -> bool {
    SECURITY_LEVELS.contains(&level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = Error::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert_eq!(error.to_string(), "Invalid key size: expected 32, got 16");
    }

    #[test]
    fn test_security_levels() {
        assert!(is_supported_security_level(1));
        assert!(is_supported_security_level(3));
        assert!(is_supported_security_level(4));
        assert!(is_supported_security_level(5));
        assert!(!is_supported_security_level(2));
        assert!(!is_supported_security_level(6));
    }
}
