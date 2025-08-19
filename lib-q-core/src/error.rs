//! Error handling for lib-Q
//!
//! This module defines the error types used throughout the library.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// The error type for lib-Q operations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[cfg(feature = "alloc")]
    InvalidAlgorithm { algorithm: String },
    #[cfg(not(feature = "alloc"))]
    InvalidAlgorithm { algorithm: &'static str },

    /// Invalid security level
    #[cfg(feature = "alloc")]
    InvalidSecurityLevel { level: u32, supported: Vec<u32> },
    #[cfg(not(feature = "alloc"))]
    InvalidSecurityLevel {
        level: u32,
        supported: &'static [u32],
    },

    /// Verification failed
    #[cfg(feature = "alloc")]
    VerificationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    VerificationFailed { operation: &'static str },

    /// Encryption failed
    #[cfg(feature = "alloc")]
    EncryptionFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    EncryptionFailed { operation: &'static str },

    /// Decryption failed
    #[cfg(feature = "alloc")]
    DecryptionFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    DecryptionFailed { operation: &'static str },

    /// Key generation failed
    #[cfg(feature = "alloc")]
    KeyGenerationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    KeyGenerationFailed { operation: &'static str },

    /// Random number generation failed
    #[cfg(feature = "alloc")]
    RandomGenerationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    RandomGenerationFailed { operation: &'static str },

    /// Memory allocation failed
    #[cfg(feature = "alloc")]
    MemoryAllocationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    MemoryAllocationFailed { operation: &'static str },

    /// Internal error
    #[cfg(feature = "alloc")]
    InternalError { operation: String, details: String },
    #[cfg(not(feature = "alloc"))]
    InternalError {
        operation: &'static str,
        details: &'static str,
    },

    /// Not implemented
    #[cfg(feature = "alloc")]
    NotImplemented { feature: String },
    #[cfg(not(feature = "alloc"))]
    NotImplemented { feature: &'static str },

    /// Unsupported operation
    #[cfg(feature = "alloc")]
    UnsupportedOperation { operation: String },
    #[cfg(not(feature = "alloc"))]
    UnsupportedOperation { operation: &'static str },

    /// Invalid state
    #[cfg(feature = "alloc")]
    InvalidState { operation: String, reason: String },
    #[cfg(not(feature = "alloc"))]
    InvalidState {
        operation: &'static str,
        reason: &'static str,
    },

    /// Invalid key format
    InvalidKeyFormat,
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
            Error::InvalidKeyFormat => {
                write!(f, "Invalid key format")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for lib-Q operations
pub type Result<T> = core::result::Result<T, Error>;

/// WASM-friendly error handling
#[cfg(feature = "wasm")]
impl Error {
    /// Get error message for WASM
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Get error type name for WASM
    pub fn error_type(&self) -> String {
        match self {
            Error::InvalidKeySize { .. } => "InvalidKeySize".to_string(),
            Error::InvalidSignatureSize { .. } => "InvalidSignatureSize".to_string(),
            Error::InvalidNonceSize { .. } => "InvalidNonceSize".to_string(),
            Error::InvalidMessageSize { .. } => "InvalidMessageSize".to_string(),
            Error::InvalidCiphertextSize { .. } => "InvalidCiphertextSize".to_string(),
            Error::InvalidPlaintextSize { .. } => "InvalidPlaintextSize".to_string(),
            Error::InvalidHashSize { .. } => "InvalidHashSize".to_string(),
            Error::InvalidAlgorithm { .. } => "InvalidAlgorithm".to_string(),
            Error::InvalidSecurityLevel { .. } => "InvalidSecurityLevel".to_string(),
            Error::VerificationFailed { .. } => "VerificationFailed".to_string(),
            Error::EncryptionFailed { .. } => "EncryptionFailed".to_string(),
            Error::DecryptionFailed { .. } => "DecryptionFailed".to_string(),
            Error::KeyGenerationFailed { .. } => "KeyGenerationFailed".to_string(),
            Error::RandomGenerationFailed { .. } => "RandomGenerationFailed".to_string(),
            Error::MemoryAllocationFailed { .. } => "MemoryAllocationFailed".to_string(),
            Error::InternalError { .. } => "InternalError".to_string(),
            Error::NotImplemented { .. } => "NotImplemented".to_string(),
            Error::UnsupportedOperation { .. } => "UnsupportedOperation".to_string(),
            Error::InvalidState { .. } => "InvalidState".to_string(),
            Error::InvalidKeyFormat => "InvalidKeyFormat".to_string(),
        }
    }
}

/// Security levels supported by lib-Q
pub const SECURITY_LEVELS: &[u32] = &[1, 3, 4, 5];

/// Get supported security levels as a Vec (for Error construction)
#[cfg(feature = "alloc")]
pub fn supported_security_levels() -> Vec<u32> {
    SECURITY_LEVELS.to_vec()
}

#[cfg(not(feature = "alloc"))]
pub fn supported_security_levels() -> &'static [u32] {
    SECURITY_LEVELS
}

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
