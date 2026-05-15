//! Error handling for lib-Q
//!
//! This module defines the error types used throughout the library.

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use alloc::{
    string::{
        String,
        ToString,
    },
    vec::Vec,
};

/// The error type for lib-Q operations
///
/// This enum represents all possible errors that can occur during cryptographic operations
/// across all libQ libraries. Each variant includes context about when the error occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// #[cfg_attr(
//     feature = "wasm",
//     derive(wasm_bindgen::FromJsValue, wasm_bindgen::IntoJsValue)
// )]
pub enum Error {
    /// Invalid key size
    ///
    /// **When it occurs:** A key (public or secret) has an incorrect size for the algorithm.
    /// **Cause:** The key data provided doesn't match the expected size for the algorithm variant.
    /// **Resolution:** Ensure the key size matches the algorithm's requirements. Check algorithm documentation for expected key sizes.
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid signature size
    ///
    /// **When it occurs:** A signature has an incorrect size for the algorithm.
    /// **Cause:** The signature data doesn't match the expected size for verification.
    /// **Resolution:** Ensure the signature was generated for the same algorithm variant and hasn't been corrupted.
    InvalidSignatureSize { expected: usize, actual: usize },

    /// Invalid nonce size
    ///
    /// **When it occurs:** A nonce has an incorrect size for the operation.
    /// **Cause:** The nonce doesn't meet the size requirements for the cryptographic operation.
    /// **Resolution:** Ensure the nonce size matches the algorithm's requirements (typically 12-16 bytes for AEAD).
    InvalidNonceSize { expected: usize, actual: usize },

    /// Invalid message size
    ///
    /// **When it occurs:** A message exceeds the maximum allowed size.
    /// **Cause:** The message is too large for the operation or algorithm limits.
    /// **Resolution:** Split the message into smaller chunks or use a different approach that supports larger messages.
    InvalidMessageSize { max: usize, actual: usize },

    /// Invalid ciphertext size
    ///
    /// **When it occurs:** A ciphertext has an incorrect size for decryption.
    /// **Cause:** The ciphertext data doesn't match the expected size for the algorithm.
    /// **Resolution:** Ensure the ciphertext was generated for the same algorithm and hasn't been corrupted.
    InvalidCiphertextSize { expected: usize, actual: usize },

    /// Invalid plaintext size
    ///
    /// **When it occurs:** A plaintext has an incorrect size for the operation.
    /// **Cause:** The plaintext doesn't meet the size requirements for encryption.
    /// **Resolution:** Verify the plaintext size matches the algorithm's requirements.
    InvalidPlaintextSize { expected: usize, actual: usize },

    /// Invalid associated data size
    ///
    /// **When it occurs:** Associated data exceeds the maximum allowed size.
    /// **Cause:** The associated data is too large for the AEAD operation.
    /// **Resolution:** Reduce the associated data size or use a different approach.
    InvalidAssociatedDataSize { max: usize, actual: usize },

    /// Invalid tag size
    ///
    /// **When it occurs:** An authentication tag has an incorrect size.
    /// **Cause:** The tag doesn't match the expected size for the AEAD algorithm.
    /// **Resolution:** Ensure the tag size matches the algorithm's requirements (typically 16 bytes).
    InvalidTagSize { expected: usize, actual: usize },

    /// Invalid hash size
    ///
    /// **When it occurs:** A hash output has an incorrect size.
    /// **Cause:** The hash size doesn't match the expected output length for the hash function.
    /// **Resolution:** Ensure the hash size matches the algorithm's output length (e.g., SHA-256 = 32 bytes).
    InvalidHashSize { expected: usize, actual: usize },

    /// Invalid algorithm
    ///
    /// **When it occurs:** An unsupported or invalid algorithm is specified.
    /// **Cause:** The algorithm identifier doesn't match any supported algorithm, or the algorithm isn't available in the current configuration.
    /// **Resolution:** Check that the algorithm is supported and that required features are enabled.
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
    ///
    /// **When it occurs:** Signature or message authentication verification fails.
    /// **Cause:** The signature is invalid, the message was tampered with, or the verification key is incorrect.
    /// **Resolution:** Verify the signature, message, and key are correct and correspond to each other.
    #[cfg(feature = "alloc")]
    VerificationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    VerificationFailed { operation: &'static str },

    /// Encryption failed
    ///
    /// **When it occurs:** Encryption or encapsulation fails to produce a valid ciphertext.
    /// **Cause:** Random number generation may have failed, or internal computation encountered an error.
    /// **Resolution:** Ensure a secure random number generator is available and functioning correctly.
    #[cfg(feature = "alloc")]
    EncryptionFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    EncryptionFailed { operation: &'static str },

    /// Decryption failed
    ///
    /// **When it occurs:** Decryption or decapsulation fails to recover the plaintext or shared secret.
    /// **Cause:** The ciphertext may be corrupted, the key may be incorrect, or authentication failed.
    /// **Resolution:** Verify the ciphertext and key are valid and correspond to each other.
    #[cfg(feature = "alloc")]
    DecryptionFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    DecryptionFailed { operation: &'static str },

    /// Key generation failed
    ///
    /// **When it occurs:** Key pair generation fails.
    /// **Cause:** Random number generation may have failed, or internal computation encountered an error.
    /// **Resolution:** Ensure a secure random number generator is available and functioning correctly.
    #[cfg(feature = "alloc")]
    KeyGenerationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    KeyGenerationFailed { operation: &'static str },

    /// Random number generation failed
    ///
    /// **When it occurs:** The random number generator fails to produce random bytes.
    /// **Cause:** The underlying RNG implementation encountered an error or is unavailable.
    /// **Resolution:** Check RNG initialization and ensure a secure random source is available.
    #[cfg(feature = "alloc")]
    RandomGenerationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    RandomGenerationFailed { operation: &'static str },

    /// Signing failed
    ///
    /// **When it occurs:** Digital signature generation fails.
    /// **Cause:** Random number generation may have failed, or internal computation encountered an error.
    /// **Resolution:** Ensure a secure random number generator is available and functioning correctly.
    #[cfg(feature = "alloc")]
    SigningFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    SigningFailed { operation: &'static str },

    /// Memory allocation failed
    ///
    /// **When it occurs:** Dynamic memory allocation fails during an operation.
    /// **Cause:** Insufficient memory is available, or allocation is not supported in the current environment.
    /// **Resolution:** Ensure sufficient memory is available, or use a no_std-compatible configuration.
    #[cfg(feature = "alloc")]
    MemoryAllocationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    MemoryAllocationFailed { operation: &'static str },

    /// Internal error
    ///
    /// **When it occurs:** An unexpected internal error occurs during cryptographic operations.
    /// **Cause:** This typically indicates a bug in the implementation or corrupted internal state.
    /// **Resolution:** Report this error as it may indicate a software bug. Check inputs and system state.
    #[cfg(feature = "alloc")]
    InternalError { operation: String, details: String },
    #[cfg(not(feature = "alloc"))]
    InternalError {
        operation: &'static str,
        details: &'static str,
    },

    /// Not implemented
    ///
    /// **When it occurs:** A requested feature or operation is not yet implemented.
    /// **Cause:** The operation is not available in the current implementation.
    /// **Resolution:** Check if an alternative approach is available, or wait for the feature to be implemented.
    #[cfg(feature = "alloc")]
    NotImplemented { feature: String },
    #[cfg(not(feature = "alloc"))]
    NotImplemented { feature: &'static str },

    /// Unsupported operation
    #[cfg(feature = "alloc")]
    UnsupportedOperation { operation: String },
    #[cfg(not(feature = "alloc"))]
    UnsupportedOperation { operation: &'static str },

    /// No `CryptoProvider` configured on the context (distinct from stub `NotImplemented`)
    #[cfg(feature = "alloc")]
    ProviderNotConfigured { operation: String },
    #[cfg(not(feature = "alloc"))]
    ProviderNotConfigured { operation: &'static str },

    /// Invalid state
    #[cfg(feature = "alloc")]
    InvalidState { operation: String, reason: String },
    #[cfg(not(feature = "alloc"))]
    InvalidState {
        operation: &'static str,
        reason: &'static str,
    },

    /// Plugin dependency error
    #[cfg(feature = "alloc")]
    PluginDependencyError {
        plugin: String,
        dependency: String,
        required_version: String,
        available_version: Option<String>,
    },
    #[cfg(not(feature = "alloc"))]
    PluginDependencyError {
        plugin: &'static str,
        dependency: &'static str,
        required_version: &'static str,
        available_version: Option<&'static str>,
    },

    /// Plugin version incompatibility
    #[cfg(feature = "alloc")]
    PluginVersionIncompatible {
        plugin: String,
        required_version: String,
        available_version: String,
    },
    #[cfg(not(feature = "alloc"))]
    PluginVersionIncompatible {
        plugin: &'static str,
        required_version: &'static str,
        available_version: &'static str,
    },

    /// Invalid key format
    InvalidKeyFormat,

    /// Invalid key with specific reason
    #[cfg(feature = "alloc")]
    InvalidKey { key_type: String, reason: String },
    #[cfg(not(feature = "alloc"))]
    InvalidKey {
        key_type: &'static str,
        reason: &'static str,
    },

    /// Unsupported algorithm
    #[cfg(feature = "alloc")]
    UnsupportedAlgorithm { algorithm: String },
    #[cfg(not(feature = "alloc"))]
    UnsupportedAlgorithm { algorithm: &'static str },

    /// Authentication failed
    #[cfg(feature = "alloc")]
    AuthenticationFailed { operation: String },
    #[cfg(not(feature = "alloc"))]
    AuthenticationFailed { operation: &'static str },

    /// Invalid randomness size
    InvalidRandomnessSize { expected: usize, actual: usize },
}

impl Error {
    /// AEAD ciphertext is shorter than the minimum length required to hold an authentication tag.
    ///
    /// This is an **operational** input error (Layer A / pre-decrypt validation). It must not be
    /// used for tag mismatch after the decrypt/verify schedule; that path uses
    /// [`Error::VerificationFailed`] or [`DecryptSemanticOutcome::AuthenticationFailed`](crate::DecryptSemanticOutcome::AuthenticationFailed).
    #[must_use]
    pub const fn aead_ciphertext_shorter_than_tag(tag_len: usize, actual_len: usize) -> Self {
        Self::InvalidCiphertextSize {
            expected: tag_len,
            actual: actual_len,
        }
    }
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
            Error::InvalidAssociatedDataSize { max, actual } => {
                write!(
                    f,
                    "Invalid associated data size: maximum {max}, got {actual}"
                )
            }
            Error::InvalidTagSize { expected, actual } => {
                write!(f, "Invalid tag size: expected {expected}, got {actual}")
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
            Error::SigningFailed { operation } => {
                write!(f, "Signing failed: {operation}")
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
            Error::ProviderNotConfigured { operation } => {
                write!(
                    f,
                    "Cryptographic provider not configured for {operation}; set a provider on the context"
                )
            }
            Error::UnsupportedOperation { operation } => {
                write!(f, "Unsupported operation: {operation}")
            }
            Error::InvalidState { operation, reason } => {
                write!(f, "Invalid state in {operation}: {reason}")
            }
            #[cfg(feature = "alloc")]
            Error::PluginDependencyError {
                plugin,
                dependency,
                required_version,
                available_version,
            } => {
                if let Some(available) = available_version {
                    write!(
                        f,
                        "Plugin '{plugin}' requires dependency '{dependency}' version {required_version}, but version {available} is available"
                    )
                } else {
                    write!(
                        f,
                        "Plugin '{plugin}' requires dependency '{dependency}' version {required_version}, but it is not available"
                    )
                }
            }
            #[cfg(not(feature = "alloc"))]
            Error::PluginDependencyError {
                plugin,
                dependency,
                required_version,
                available_version,
            } => {
                if let Some(available) = available_version {
                    write!(
                        f,
                        "Plugin '{}' requires dependency '{}' version {}, but version {} is available",
                        plugin, dependency, required_version, available
                    )
                } else {
                    write!(
                        f,
                        "Plugin '{}' requires dependency '{}' version {}, but it is not available",
                        plugin, dependency, required_version
                    )
                }
            }
            #[cfg(feature = "alloc")]
            Error::PluginVersionIncompatible {
                plugin,
                required_version,
                available_version,
            } => {
                write!(
                    f,
                    "Plugin '{plugin}' version {available_version} is incompatible with required version {required_version}"
                )
            }
            #[cfg(not(feature = "alloc"))]
            Error::PluginVersionIncompatible {
                plugin,
                required_version,
                available_version,
            } => {
                write!(
                    f,
                    "Plugin '{}' version {} is incompatible with required version {}",
                    plugin, available_version, required_version
                )
            }
            Error::InvalidKeyFormat => {
                write!(f, "Invalid key format")
            }
            Error::InvalidKey { key_type, reason } => {
                write!(f, "Invalid {key_type}: {reason}")
            }
            Error::UnsupportedAlgorithm { algorithm } => {
                write!(f, "Unsupported algorithm: {algorithm}")
            }
            Error::AuthenticationFailed { operation } => {
                write!(f, "Authentication failed: {operation}")
            }
            Error::InvalidRandomnessSize { expected, actual } => {
                write!(
                    f,
                    "Invalid randomness size: expected {expected}, got {actual}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// WASM error conversion
#[cfg(feature = "wasm")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(error: Error) -> Self {
        use crate::wasm::error::error_to_js_value;
        error_to_js_value(error)
    }
}

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
            Error::SigningFailed { .. } => "SigningFailed".to_string(),
            Error::MemoryAllocationFailed { .. } => "MemoryAllocationFailed".to_string(),
            Error::InternalError { .. } => "InternalError".to_string(),
            Error::NotImplemented { .. } => "NotImplemented".to_string(),
            Error::ProviderNotConfigured { .. } => "ProviderNotConfigured".to_string(),
            Error::UnsupportedOperation { .. } => "UnsupportedOperation".to_string(),
            Error::InvalidState { .. } => "InvalidState".to_string(),
            Error::InvalidAssociatedDataSize { .. } => "InvalidAssociatedDataSize".to_string(),
            Error::InvalidTagSize { .. } => "InvalidTagSize".to_string(),
            Error::PluginDependencyError { .. } => "PluginDependencyError".to_string(),
            Error::PluginVersionIncompatible { .. } => "PluginVersionIncompatible".to_string(),
            Error::InvalidKeyFormat => "InvalidKeyFormat".to_string(),
            Error::InvalidKey { .. } => "InvalidKey".to_string(),
            Error::UnsupportedAlgorithm { .. } => "UnsupportedAlgorithm".to_string(),
            Error::AuthenticationFailed { .. } => "AuthenticationFailed".to_string(),
            Error::InvalidRandomnessSize { .. } => "InvalidRandomnessSize".to_string(),
        }
    }
}

#[cfg(feature = "wasm")]
impl From<wasm_bindgen::JsValue> for Error {
    fn from(_js_value: wasm_bindgen::JsValue) -> Self {
        // Convert JsValue to a generic internal error
        // This is used when WASM code needs to convert JsValue errors back to Error
        Error::InternalError {
            operation: "WASM operation".to_string(),
            details: "WASM error conversion".to_string(),
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
        #[cfg(not(feature = "std"))]
        use alloc::string::ToString;

        let error = Error::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert_eq!(error.to_string(), "Invalid key size: expected 32, got 16");
    }

    #[test]
    fn test_invalid_key_error_display() {
        #[cfg(feature = "alloc")]
        {
            let error = Error::InvalidKey {
                key_type: "public key".to_string(),
                reason: "cannot be used for encapsulation".to_string(),
            };
            assert_eq!(
                error.to_string(),
                "Invalid public key: cannot be used for encapsulation"
            );
        }
        #[cfg(not(feature = "alloc"))]
        {
            #[cfg(not(feature = "std"))]
            use alloc::string::ToString;

            let error = Error::InvalidKey {
                key_type: "public key",
                reason: "cannot be used for encapsulation",
            };
            assert_eq!(
                error.to_string(),
                "Invalid public key: cannot be used for encapsulation"
            );
        }
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
