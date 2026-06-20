//! Error type for the blind-token flow.

use core::fmt;

/// Errors surfaced by the blind / blind-sign / unblind operations and the token codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlindTokenError {
    /// Underlying lattice proof generation failed (rejection limit / bad parameters).
    Proof,
    /// Module dimensions did not line up while combining openings.
    Mismatch,
    /// Token bytes did not decode to the expected structure.
    Encoding,
    /// Token payload exceeded the byte budget.
    BudgetExceeded {
        /// Observed length.
        actual: usize,
        /// Configured budget.
        budget: usize,
    },
    /// Wire version byte did not match.
    WireVersionMismatch {
        /// Expected version.
        expected: u8,
        /// Found version.
        found: u8,
    },
    /// Wire profile byte did not match.
    WireProfileMismatch {
        /// Expected profile id.
        expected: u8,
        /// Found profile id.
        found: u8,
    },
    /// Payload ended before all declared fields were read.
    WireTruncated,
    /// A length value did not fit the wire width.
    LengthOverflow,
}

impl fmt::Display for BlindTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof => write!(f, "lattice proof generation failed"),
            Self::Mismatch => write!(f, "mismatched module dimensions"),
            Self::Encoding => write!(f, "token encoding error"),
            Self::BudgetExceeded { actual, budget } => {
                write!(f, "token payload exceeds budget: {actual} > {budget}")
            }
            Self::WireVersionMismatch { expected, found } => {
                write!(
                    f,
                    "wire version mismatch: expected {expected}, found {found}"
                )
            }
            Self::WireProfileMismatch { expected, found } => {
                write!(
                    f,
                    "wire profile mismatch: expected {expected}, found {found}"
                )
            }
            Self::WireTruncated => write!(f, "wire payload truncated"),
            Self::LengthOverflow => write!(f, "length conversion overflow"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlindTokenError {}
