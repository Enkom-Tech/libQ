// Allow clippy warnings in error handling code
// These are legitimate patterns for error reporting and formatting
#![allow(
    clippy::uninlined_format_args,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

//! Error types for lib-q-rng
//!
//! This module defines comprehensive error types for random number generation
//! operations, providing detailed information about failure modes and recovery
//! strategies.

#[cfg(not(feature = "std"))]
use alloc::string::String;
use core::fmt;

/// Result type alias for lib-q-rng operations
pub type Result<T> = core::result::Result<T, Error>;

/// Comprehensive error types for RNG operations
///
/// This enum provides detailed error information for various failure modes
/// in random number generation, enabling proper error handling and recovery.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Entropy source is not available or failed
    EntropySourceUnavailable {
        /// Description of the entropy source failure
        source: &'static str,
        /// Additional context about the failure
        context: Option<&'static str>,
    },

    /// Insufficient entropy for cryptographic operations
    InsufficientEntropy {
        /// Required entropy bits
        required: usize,
        /// Available entropy bits
        available: usize,
        /// Quality assessment of available entropy
        quality: f64,
    },

    /// Entropy validation failed
    EntropyValidationFailed {
        /// Reason for validation failure
        reason: &'static str,
        /// Entropy quality score (0.0 to 1.0)
        quality: f64,
        /// Additional validation details
        details: Option<&'static str>,
    },

    /// Hardware RNG failure
    HardwareRngFailed {
        /// Hardware device identifier
        device: &'static str,
        /// Error code or status
        status: Option<u32>,
        /// Additional error details
        details: Option<&'static str>,
    },

    /// Platform-specific RNG failure
    PlatformRngFailed {
        /// Platform identifier
        platform: &'static str,
        /// Error code or status
        code: Option<i32>,
        /// Additional error details
        details: Option<&'static str>,
    },

    /// Invalid configuration or parameters
    InvalidConfiguration {
        /// Parameter that caused the error
        parameter: &'static str,
        /// Expected value or range
        #[cfg(feature = "alloc")]
        expected: String,
        #[cfg(not(feature = "alloc"))]
        expected: &'static str,
        /// Actual value provided
        #[cfg(feature = "alloc")]
        actual: String,
        #[cfg(not(feature = "alloc"))]
        actual: &'static str,
    },

    /// Memory allocation failure
    MemoryAllocationFailed {
        /// Size of allocation that failed
        size: usize,
        /// Additional context
        context: Option<&'static str>,
    },

    /// Thread safety violation
    ThreadSafetyViolation {
        /// Description of the violation
        violation: &'static str,
        /// Additional context
        context: Option<&'static str>,
    },

    /// Cryptographic operation failed
    CryptographicFailure {
        /// Operation that failed
        operation: &'static str,
        /// Error code or status
        code: Option<u32>,
        /// Additional details
        details: Option<&'static str>,
    },

    /// Test vector validation failed
    TestVectorValidationFailed {
        /// Test vector identifier
        vector_id: &'static str,
        /// Expected value
        #[cfg(feature = "alloc")]
        expected: String,
        #[cfg(not(feature = "alloc"))]
        expected: &'static str,
        /// Actual value
        #[cfg(feature = "alloc")]
        actual: String,
        #[cfg(not(feature = "alloc"))]
        actual: &'static str,
    },

    /// Feature not available
    FeatureNotAvailable {
        /// Feature that is not available
        feature: &'static str,
        /// Required features for this functionality
        required_features: &'static [&'static str],
    },

    /// Internal implementation error
    InternalError {
        /// Component that failed
        component: &'static str,
        /// Error message
        message: &'static str,
    },
}

impl Error {
    /// Create a new entropy source unavailable error
    pub fn entropy_source_unavailable(source: &'static str) -> Self {
        Self::EntropySourceUnavailable {
            source,
            context: None,
        }
    }

    /// Create a new entropy source unavailable error with context
    pub fn entropy_source_unavailable_with_context(
        source: &'static str,
        context: &'static str,
    ) -> Self {
        Self::EntropySourceUnavailable {
            source,
            context: Some(context),
        }
    }

    /// Create a new insufficient entropy error
    pub fn insufficient_entropy(required: usize, available: usize, quality: f64) -> Self {
        Self::InsufficientEntropy {
            required,
            available,
            quality,
        }
    }

    /// Create a new entropy validation failed error
    pub fn entropy_validation_failed(reason: &'static str, quality: f64) -> Self {
        Self::EntropyValidationFailed {
            reason,
            quality,
            details: None,
        }
    }

    /// Create a new entropy validation failed error with details
    pub fn entropy_validation_failed_with_details(
        reason: &'static str,
        quality: f64,
        details: &'static str,
    ) -> Self {
        Self::EntropyValidationFailed {
            reason,
            quality,
            details: Some(details),
        }
    }

    /// Create a new hardware RNG failed error
    pub fn hardware_rng_failed(device: &'static str) -> Self {
        Self::HardwareRngFailed {
            device,
            status: None,
            details: None,
        }
    }

    /// Create a new hardware RNG failed error with status
    pub fn hardware_rng_failed_with_status(
        device: &'static str,
        status: u32,
        details: &'static str,
    ) -> Self {
        Self::HardwareRngFailed {
            device,
            status: Some(status),
            details: Some(details),
        }
    }

    /// Create a new platform RNG failed error
    pub fn platform_rng_failed(platform: &'static str) -> Self {
        Self::PlatformRngFailed {
            platform,
            code: None,
            details: None,
        }
    }

    /// Create a new platform RNG failed error with code
    pub fn platform_rng_failed_with_code(
        platform: &'static str,
        code: i32,
        details: &'static str,
    ) -> Self {
        Self::PlatformRngFailed {
            platform,
            code: Some(code),
            details: Some(details),
        }
    }

    /// Create a new invalid configuration error
    pub fn invalid_configuration(
        parameter: &'static str,
        expected: &'static str,
        actual: &'static str,
    ) -> Self {
        Self::InvalidConfiguration {
            parameter,
            #[cfg(feature = "alloc")]
            expected: expected.to_string(),
            #[cfg(not(feature = "alloc"))]
            expected,
            #[cfg(feature = "alloc")]
            actual: actual.to_string(),
            #[cfg(not(feature = "alloc"))]
            actual,
        }
    }

    /// Create a new memory allocation failed error
    pub fn memory_allocation_failed(size: usize) -> Self {
        Self::MemoryAllocationFailed {
            size,
            context: None,
        }
    }

    /// Create a new memory allocation failed error with context
    pub fn memory_allocation_failed_with_context(size: usize, context: &'static str) -> Self {
        Self::MemoryAllocationFailed {
            size,
            context: Some(context),
        }
    }

    /// Create a new thread safety violation error
    pub fn thread_safety_violation(violation: &'static str) -> Self {
        Self::ThreadSafetyViolation {
            violation,
            context: None,
        }
    }

    /// Create a new thread safety violation error with context
    pub fn thread_safety_violation_with_context(
        violation: &'static str,
        context: &'static str,
    ) -> Self {
        Self::ThreadSafetyViolation {
            violation,
            context: Some(context),
        }
    }

    /// Create a new cryptographic failure error
    pub fn cryptographic_failure(operation: &'static str) -> Self {
        Self::CryptographicFailure {
            operation,
            code: None,
            details: None,
        }
    }

    /// Create a new cryptographic failure error with code
    pub fn cryptographic_failure_with_code(
        operation: &'static str,
        code: u32,
        details: &'static str,
    ) -> Self {
        Self::CryptographicFailure {
            operation,
            code: Some(code),
            details: Some(details),
        }
    }

    /// Create a new test vector validation failed error
    pub fn test_vector_validation_failed(
        vector_id: &'static str,
        expected: &'static str,
        actual: &'static str,
    ) -> Self {
        Self::TestVectorValidationFailed {
            vector_id,
            #[cfg(feature = "alloc")]
            expected: expected.to_string(),
            #[cfg(not(feature = "alloc"))]
            expected,
            #[cfg(feature = "alloc")]
            actual: actual.to_string(),
            #[cfg(not(feature = "alloc"))]
            actual,
        }
    }

    /// Create a new feature not available error
    pub fn feature_not_available(
        feature: &'static str,
        required_features: &'static [&'static str],
    ) -> Self {
        Self::FeatureNotAvailable {
            feature,
            required_features,
        }
    }

    /// Create a new internal error
    pub fn internal_error(component: &'static str, message: &'static str) -> Self {
        Self::InternalError { component, message }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::EntropySourceUnavailable { .. } |
                Self::PlatformRngFailed { .. } |
                Self::HardwareRngFailed { .. }
        )
    }

    /// Check if this error indicates insufficient entropy
    pub fn is_entropy_related(&self) -> bool {
        matches!(
            self,
            Self::EntropySourceUnavailable { .. } |
                Self::InsufficientEntropy { .. } |
                Self::EntropyValidationFailed { .. }
        )
    }

    /// Get a human-readable error description
    pub fn description(&self) -> &'static str {
        match self {
            Self::EntropySourceUnavailable { .. } => "Entropy source is not available",
            Self::InsufficientEntropy { .. } => "Insufficient entropy for cryptographic operations",
            Self::EntropyValidationFailed { .. } => "Entropy validation failed",
            Self::HardwareRngFailed { .. } => "Hardware random number generator failed",
            Self::PlatformRngFailed { .. } => "Platform random number generator failed",
            Self::InvalidConfiguration { .. } => "Invalid configuration or parameters",
            Self::MemoryAllocationFailed { .. } => "Memory allocation failed",
            Self::ThreadSafetyViolation { .. } => "Thread safety violation detected",
            Self::CryptographicFailure { .. } => "Cryptographic operation failed",
            Self::TestVectorValidationFailed { .. } => "Test vector validation failed",
            Self::FeatureNotAvailable { .. } => "Required feature is not available",
            Self::InternalError { .. } => "Internal implementation error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropySourceUnavailable { source, context } => {
                write!(f, "Entropy source '{}' is not available", source)?;
                if let Some(ctx) = context {
                    write!(f, ": {}", ctx)?;
                }
                Ok(())
            }
            Self::InsufficientEntropy {
                required,
                available,
                quality,
            } => {
                write!(
                    f,
                    "Insufficient entropy: required {} bits, available {} bits (quality: {:.2})",
                    required, available, quality
                )
            }
            Self::EntropyValidationFailed {
                reason,
                quality,
                details,
            } => {
                write!(
                    f,
                    "Entropy validation failed: {} (quality: {:.2})",
                    reason, quality
                )?;
                if let Some(details) = details {
                    write!(f, ": {}", details)?;
                }
                Ok(())
            }
            Self::HardwareRngFailed {
                device,
                status,
                details,
            } => {
                write!(f, "Hardware RNG '{}' failed", device)?;
                if let Some(status) = status {
                    write!(f, " (status: {})", status)?;
                }
                if let Some(details) = details {
                    write!(f, ": {}", details)?;
                }
                Ok(())
            }
            Self::PlatformRngFailed {
                platform,
                code,
                details,
            } => {
                write!(f, "Platform RNG '{}' failed", platform)?;
                if let Some(code) = code {
                    write!(f, " (code: {})", code)?;
                }
                if let Some(details) = details {
                    write!(f, ": {}", details)?;
                }
                Ok(())
            }
            Self::InvalidConfiguration {
                parameter,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid configuration for '{}': expected {}, got {}",
                    parameter, expected, actual
                )
            }
            Self::MemoryAllocationFailed { size, context } => {
                write!(f, "Memory allocation failed for {} bytes", size)?;
                if let Some(ctx) = context {
                    write!(f, ": {}", ctx)?;
                }
                Ok(())
            }
            Self::ThreadSafetyViolation { violation, context } => {
                write!(f, "Thread safety violation: {}", violation)?;
                if let Some(ctx) = context {
                    write!(f, ": {}", ctx)?;
                }
                Ok(())
            }
            Self::CryptographicFailure {
                operation,
                code,
                details,
            } => {
                write!(f, "Cryptographic operation '{}' failed", operation)?;
                if let Some(code) = code {
                    write!(f, " (code: {})", code)?;
                }
                if let Some(details) = details {
                    write!(f, ": {}", details)?;
                }
                Ok(())
            }
            Self::TestVectorValidationFailed {
                vector_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Test vector '{}' validation failed: expected {}, got {}",
                    vector_id, expected, actual
                )
            }
            Self::FeatureNotAvailable {
                feature,
                required_features,
            } => {
                write!(f, "Feature '{}' is not available", feature)?;
                if !required_features.is_empty() {
                    #[cfg(feature = "alloc")]
                    {
                        write!(f, " (required features: {})", required_features.join(", "))?;
                    }
                    #[cfg(not(feature = "alloc"))]
                    {
                        write!(f, " (required features: {:?})", required_features)?;
                    }
                }
                Ok(())
            }
            Self::InternalError { component, message } => {
                write!(f, "Internal error in '{}': {}", component, message)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::entropy_source_unavailable("test_source");
        assert_eq!(err.description(), "Entropy source is not available");
        assert!(err.is_entropy_related());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = Error::insufficient_entropy(256, 128, 0.5);
        let display = format!("{}", err);
        assert!(display.contains("Insufficient entropy"));
        assert!(display.contains("256"));
        assert!(display.contains("128"));
        assert!(display.contains("0.50"));
    }

    #[test]
    fn test_error_types() {
        let entropy_err = Error::entropy_source_unavailable("test");
        assert!(entropy_err.is_entropy_related());

        let config_err = Error::invalid_configuration("param", "expected", "actual");
        assert!(!config_err.is_entropy_related());
        assert!(!config_err.is_recoverable());
    }
}
