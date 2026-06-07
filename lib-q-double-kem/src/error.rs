//! Error types for the provisional double-KEM profile.

use core::fmt;

/// Errors returned by the double-KEM API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoubleKemError {
    /// Input wire length is invalid.
    InvalidWireLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Failed to decode wire layout.
    InvalidWireEncoding,
    /// Encapsulation operation failed.
    EncapsulationFailed,
    /// Decapsulation operation failed.
    DecapsulationFailed,
}

impl fmt::Display for DoubleKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWireLength { expected, actual } => {
                write!(f, "invalid wire length: expected {expected}, got {actual}")
            }
            Self::InvalidWireEncoding => write!(f, "invalid MAUL wire encoding"),
            Self::EncapsulationFailed => write!(f, "ML-KEM encapsulation failed"),
            Self::DecapsulationFailed => write!(f, "ML-KEM decapsulation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DoubleKemError {}
