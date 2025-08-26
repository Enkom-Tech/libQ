//! HPKE-specific error types

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt;

/// HPKE-specific errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeError {
    /// Open error - decryption failed
    OpenError,
    /// Invalid configuration
    InvalidConfig,
    /// Invalid input parameters
    InvalidInput,
    /// Unknown HPKE mode
    UnknownMode,
    /// Inconsistent PSK input
    InconsistentPsk,
    /// PSK required but missing
    MissingPsk,
    /// PSK provided but not needed
    UnnecessaryPsk,
    /// PSK too short (needs 32+ bytes)
    InsecurePsk,
    /// Crypto library error
    CryptoError(String),
    /// Message limit reached for this AEAD key/nonce
    MessageLimitReached,
    /// Insufficient randomness
    InsufficientRandomness,
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HpkeError::OpenError => write!(f, "HPKE open error"),
            HpkeError::InvalidConfig => write!(f, "Invalid HPKE configuration"),
            HpkeError::InvalidInput => write!(f, "Invalid HPKE input"),
            HpkeError::UnknownMode => write!(f, "Unknown HPKE mode"),
            HpkeError::InconsistentPsk => write!(f, "Inconsistent PSK input"),
            HpkeError::MissingPsk => write!(f, "PSK required but missing"),
            HpkeError::UnnecessaryPsk => write!(f, "PSK provided but not needed"),
            HpkeError::InsecurePsk => write!(f, "PSK too short (needs 32+ bytes)"),
            HpkeError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            HpkeError::MessageLimitReached => write!(f, "Message limit reached"),
            HpkeError::InsufficientRandomness => write!(f, "Insufficient randomness"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}

impl From<HpkeError> for lib_q_core::Error {
    fn from(err: HpkeError) -> Self {
        match err {
            HpkeError::OpenError => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "HPKE decryption failed",
            },
            HpkeError::InvalidConfig => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "Invalid HPKE configuration",
            },
            HpkeError::InvalidInput => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "Invalid HPKE input",
            },
            HpkeError::UnknownMode => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "Unknown HPKE mode",
            },
            HpkeError::InconsistentPsk => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "Inconsistent PSK input",
            },
            HpkeError::MissingPsk => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "PSK required but missing",
            },
            HpkeError::UnnecessaryPsk => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "PSK provided but not needed",
            },
            HpkeError::InsecurePsk => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "PSK too short",
            },
            HpkeError::CryptoError(msg) => lib_q_core::Error::NotImplemented { feature: msg },
            HpkeError::MessageLimitReached => lib_q_core::Error::InvalidAlgorithm {
                algorithm: "HPKE message limit reached",
            },
            HpkeError::InsufficientRandomness => lib_q_core::Error::NotImplemented {
                feature: String::from("Insufficient randomness"),
            },
        }
    }
}
