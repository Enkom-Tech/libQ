//! Enhanced error types for HPKE operations with structured context

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{
        String,
        ToString,
    },
};

use crate::types::*;

/// Enhanced HPKE error types with structured context
#[derive(Debug, Clone, PartialEq)]
pub enum HpkeError {
    /// KEM-related errors with algorithm and operation context
    KemError {
        /// The KEM algorithm that failed
        algorithm: HpkeKem,
        /// The operation that failed
        operation: KemOperation,
        /// The cause of the failure
        cause: String,
    },
    /// KDF-related errors with algorithm and operation context
    KdfError {
        /// The KDF algorithm that failed
        algorithm: HpkeKdf,
        /// The operation that failed
        operation: KdfOperation,
        /// The cause of the failure
        cause: String,
    },
    /// AEAD-related errors with algorithm and operation context
    AeadError {
        /// The AEAD algorithm that failed
        algorithm: HpkeAead,
        /// The operation that failed
        operation: AeadOperation,
        /// The cause of the failure
        cause: String,
    },
    /// Security validation errors with specific validation type
    SecurityError {
        /// The type of security validation that failed
        validation: SecurityValidation,
        /// The cause of the failure
        cause: String,
    },
    /// Protocol-level errors with stage information
    ProtocolError {
        /// The protocol stage that failed
        stage: ProtocolStage,
        /// The cause of the failure
        cause: String,
    },
    /// Configuration errors
    ConfigError {
        /// The setting that caused the error
        setting: String,
        /// The cause of the failure
        cause: String,
    },
    /// Generic cryptographic errors
    CryptoError(String),
    /// Invalid input parameters
    InvalidInput {
        /// The parameter name
        parameter: String,
        /// The invalid value
        value: String,
        /// Expected value or format
        expected: String,
    },
    /// Feature not enabled
    FeatureNotEnabled {
        /// The feature name
        feature: String,
    },
    /// Not implemented (for development)
    NotImplemented {
        /// The feature name
        feature: String,
    },
    /// PSK parameters do not match the sender's commitment, or PSK / PSK ID pairing is invalid.
    ///
    /// When [`crate::HpkePskWireFormat::LibQCommitmentSuffix`](crate::HpkePskWireFormat::LibQCommitmentSuffix)
    /// is used in PSK or AuthPSK mode, the receiver returns this error if the KDF-derived commitment
    /// disagrees with the local `(psk, psk_id)` before key schedule. With strict RFC 9180 PSK wire
    /// format, wrong PSK material is not detected here (typically AEAD open fails instead).
    InconsistentPsk,
}

/// KEM operation types for error context
#[derive(Debug, Clone, PartialEq)]
pub enum KemOperation {
    /// Key pair generation operation
    KeyGeneration,
    /// Key encapsulation operation
    Encapsulation,
    /// Key decapsulation operation
    Decapsulation,
    /// Key validation operation
    KeyValidation,
}

/// KDF operation types for error context
#[derive(Debug, Clone, PartialEq)]
pub enum KdfOperation {
    /// Key extraction operation
    Extract,
    /// Key expansion operation
    Expand,
    /// Key validation operation
    Validation,
}

/// AEAD operation types for error context
#[derive(Debug, Clone, PartialEq)]
pub enum AeadOperation {
    /// Encryption/sealing operation
    Seal,
    /// Decryption/opening operation
    Open,
    /// Key validation operation
    KeyValidation,
    /// Nonce validation operation
    NonceValidation,
    /// Ciphertext validation operation
    CiphertextValidation,
}

/// Security validation types for error context
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityValidation {
    /// Key length validation
    KeyLength,
    /// Nonce length validation
    NonceLength,
    /// Ciphertext length validation
    CiphertextLength,
    /// Zero key rejection
    ZeroKeyRejection,
    /// Constant time comparison
    ConstantTimeComparison,
    /// Input sanitization
    InputSanitization,
}

/// Protocol stage types for error context
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolStage {
    /// Key schedule stage
    KeySchedule,
    /// Suite ID construction stage
    SuiteIdConstruction,
    /// Labeled extract stage
    LabeledExtract,
    /// Labeled expand stage
    LabeledExpand,
    /// Context setup stage
    ContextSetup,
    /// Message sealing stage
    MessageSealing,
    /// Message opening stage
    MessageOpening,
    /// Key export stage
    KeyExport,
}

impl HpkeError {
    /// Create a KEM error with context
    pub fn kem_error(
        algorithm: HpkeKem,
        operation: KemOperation,
        cause: impl Into<String>,
    ) -> Self {
        Self::KemError {
            algorithm,
            operation,
            cause: cause.into(),
        }
    }

    /// Create a KDF error with context
    pub fn kdf_error(
        algorithm: HpkeKdf,
        operation: KdfOperation,
        cause: impl Into<String>,
    ) -> Self {
        Self::KdfError {
            algorithm,
            operation,
            cause: cause.into(),
        }
    }

    /// Create an AEAD error with context
    pub fn aead_error(
        algorithm: HpkeAead,
        operation: AeadOperation,
        cause: impl Into<String>,
    ) -> Self {
        Self::AeadError {
            algorithm,
            operation,
            cause: cause.into(),
        }
    }

    /// Create a security error with context
    pub fn security_error(validation: SecurityValidation, cause: impl Into<String>) -> Self {
        Self::SecurityError {
            validation,
            cause: cause.into(),
        }
    }

    /// Create a protocol error with context
    pub fn protocol_error(stage: ProtocolStage, cause: impl Into<String>) -> Self {
        Self::ProtocolError {
            stage,
            cause: cause.into(),
        }
    }

    /// Create an invalid input error with context
    pub fn invalid_input(
        parameter: impl Into<String>,
        value: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self::InvalidInput {
            parameter: parameter.into(),
            value: value.into(),
            expected: expected.into(),
        }
    }

    /// Create a feature not enabled error
    pub fn feature_not_enabled(feature: impl Into<String>) -> Self {
        Self::FeatureNotEnabled {
            feature: feature.into(),
        }
    }

    /// Create a not implemented error
    pub fn not_implemented(feature: impl Into<String>) -> Self {
        Self::NotImplemented {
            feature: feature.into(),
        }
    }
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HpkeError::KemError {
                algorithm,
                operation,
                cause,
            } => {
                write!(f, "KEM error in {:?} {:?}: {}", algorithm, operation, cause)
            }
            HpkeError::KdfError {
                algorithm,
                operation,
                cause,
            } => {
                write!(f, "KDF error in {:?} {:?}: {}", algorithm, operation, cause)
            }
            HpkeError::AeadError {
                algorithm,
                operation,
                cause,
            } => {
                write!(
                    f,
                    "AEAD error in {:?} {:?}: {}",
                    algorithm, operation, cause
                )
            }
            HpkeError::SecurityError { validation, cause } => {
                write!(
                    f,
                    "Security validation error in {:?}: {}",
                    validation, cause
                )
            }
            HpkeError::ProtocolError { stage, cause } => {
                write!(f, "Protocol error in {:?}: {}", stage, cause)
            }
            HpkeError::ConfigError { setting, cause } => {
                write!(f, "Configuration error for {}: {}", setting, cause)
            }
            HpkeError::CryptoError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
            HpkeError::InvalidInput {
                parameter,
                value,
                expected,
            } => {
                write!(
                    f,
                    "Invalid input for {}: got '{}', expected {}",
                    parameter, value, expected
                )
            }
            HpkeError::FeatureNotEnabled { feature } => {
                write!(f, "Feature not enabled: {}", feature)
            }
            HpkeError::NotImplemented { feature } => {
                write!(f, "Not implemented: {}", feature)
            }
            HpkeError::InconsistentPsk => {
                write!(f, "Inconsistent PSK usage")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HpkeError {}

// Error conversion to lib_q_core::Error
impl From<HpkeError> for lib_q_core::Error {
    fn from(err: HpkeError) -> Self {
        match err {
            HpkeError::KemError {
                algorithm,
                operation,
                cause,
            } => lib_q_core::Error::InternalError {
                operation: format!("KEM {:?} {:?}", algorithm, operation),
                details: cause,
            },
            HpkeError::KdfError {
                algorithm,
                operation,
                cause,
            } => lib_q_core::Error::InternalError {
                operation: format!("KDF {:?} {:?}", algorithm, operation),
                details: cause,
            },
            HpkeError::AeadError {
                algorithm,
                operation,
                cause,
            } => lib_q_core::Error::InternalError {
                operation: format!("AEAD {:?} {:?}", algorithm, operation),
                details: cause,
            },
            HpkeError::SecurityError { validation, cause } => lib_q_core::Error::InternalError {
                operation: format!("Security {:?}", validation),
                details: cause,
            },
            HpkeError::ProtocolError { stage, cause } => lib_q_core::Error::InternalError {
                operation: format!("Protocol {:?}", stage),
                details: cause,
            },
            HpkeError::ConfigError { setting, cause } => lib_q_core::Error::InternalError {
                operation: format!("Config {}", setting),
                details: cause,
            },
            HpkeError::CryptoError(msg) => lib_q_core::Error::InternalError {
                operation: "Cryptographic operation".to_string(),
                details: msg,
            },
            HpkeError::InvalidInput {
                parameter,
                value,
                expected,
            } => lib_q_core::Error::InternalError {
                operation: format!("Input validation for {}", parameter),
                details: format!("got '{}', expected {}", value, expected),
            },
            HpkeError::FeatureNotEnabled { feature } => lib_q_core::Error::InternalError {
                operation: "Feature check".to_string(),
                details: format!("Feature not enabled: {}", feature),
            },
            HpkeError::NotImplemented { feature } => lib_q_core::Error::InternalError {
                operation: "Implementation".to_string(),
                details: format!("Not implemented: {}", feature),
            },
            HpkeError::InconsistentPsk => lib_q_core::Error::InternalError {
                operation: "PSK validation".to_string(),
                details: "Inconsistent PSK usage".to_string(),
            },
        }
    }
}

/// Result type alias for HPKE operations
pub type HpkeResult<T> = Result<T, HpkeError>;

/// Convenience macros for creating errors
///
/// Creates a KEM error with algorithm, operation, and message
#[macro_export]
macro_rules! kem_err {
    ($alg:expr, $op:expr, $msg:expr) => {
        HpkeError::kem_error($alg, $op, $msg)
    };
}

/// Creates a KDF error with algorithm, operation, and message
#[macro_export]
macro_rules! kdf_err {
    ($alg:expr, $op:expr, $msg:expr) => {
        HpkeError::kdf_error($alg, $op, $msg)
    };
}

/// Creates an AEAD error with algorithm, operation, and message
#[macro_export]
macro_rules! aead_err {
    ($alg:expr, $op:expr, $msg:expr) => {
        HpkeError::aead_error($alg, $op, $msg)
    };
}

/// Creates a security error with validation type and message
#[macro_export]
macro_rules! security_err {
    ($validation:expr, $msg:expr) => {
        HpkeError::security_error($validation, $msg)
    };
}

/// Creates a protocol error with stage and message
#[macro_export]
macro_rules! protocol_err {
    ($stage:expr, $msg:expr) => {
        HpkeError::protocol_error($stage, $msg)
    };
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_core::Error as CoreError;

    use super::*;

    #[test]
    fn display_formats_all_error_variants() {
        let cases = vec![
            HpkeError::kem_error(HpkeKem::MlKem512, KemOperation::Encapsulation, "kem fail"),
            HpkeError::kdf_error(HpkeKdf::HkdfShake256, KdfOperation::Expand, "kdf fail"),
            HpkeError::aead_error(HpkeAead::Saturnin256, AeadOperation::Open, "aead fail"),
            HpkeError::security_error(SecurityValidation::NonceLength, "security fail"),
            HpkeError::protocol_error(ProtocolStage::ContextSetup, "protocol fail"),
            HpkeError::ConfigError {
                setting: "mode".into(),
                cause: "bad".into(),
            },
            HpkeError::CryptoError("crypto fail".into()),
            HpkeError::invalid_input("nonce", "3", "16 bytes"),
            HpkeError::feature_not_enabled("saturnin"),
            HpkeError::not_implemented("auth mode"),
            HpkeError::InconsistentPsk,
        ];

        for err in cases {
            let text = err.to_string();
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn conversion_to_core_error_maps_all_variants() {
        let cases = vec![
            HpkeError::kem_error(HpkeKem::MlKem768, KemOperation::Decapsulation, "kem"),
            HpkeError::kdf_error(HpkeKdf::HkdfSha3_512, KdfOperation::Validation, "kdf"),
            HpkeError::aead_error(
                HpkeAead::DuplexSpongeAead,
                AeadOperation::CiphertextValidation,
                "aead",
            ),
            HpkeError::security_error(SecurityValidation::KeyLength, "security"),
            HpkeError::protocol_error(ProtocolStage::MessageOpening, "protocol"),
            HpkeError::ConfigError {
                setting: "suite".into(),
                cause: "unsupported".into(),
            },
            HpkeError::CryptoError("crypto".into()),
            HpkeError::invalid_input("key", "short", "32 bytes"),
            HpkeError::feature_not_enabled("ml-kem"),
            HpkeError::not_implemented("export"),
            HpkeError::InconsistentPsk,
        ];

        for err in cases {
            let converted: CoreError = err.into();
            match converted {
                CoreError::InternalError { operation, details } => {
                    assert!(!operation.is_empty());
                    assert!(!details.is_empty());
                }
                other => panic!("unexpected conversion result: {other:?}"),
            }
        }
    }
}
