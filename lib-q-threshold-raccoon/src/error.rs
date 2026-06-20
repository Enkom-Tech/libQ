//! Error type for the lattice threshold signature.

use core::fmt;

/// Errors surfaced by the threshold-signature operations and wire codecs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RaccoonError {
    /// Profile identifier or geometry does not match the supported `V1` profile.
    InvalidProfile,
    /// Threshold is zero, exceeds the party count, or exceeds `max_parties`.
    InvalidThreshold,
    /// Party / share count is zero or exceeds `max_parties`.
    InvalidShareCount,
    /// The signer subset is empty, too small, or has a repeated/zero index.
    InvalidSignerSet,
    /// A share index is out of the valid `1..=n` range.
    InvalidIndex {
        /// The offending index.
        index: u8,
    },
    /// A share/commitment/signature did not decode to the expected geometry.
    Encoding,
    /// Signing exhausted its Fiat–Shamir abort budget (vanishingly unlikely).
    SignExhausted,
    /// Wire payload ended before all declared fields were read.
    WireTruncated,
    /// Wire payload exceeded the byte budget.
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
    /// A length value did not fit the wire width.
    LengthOverflow,
}

impl fmt::Display for RaccoonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile => write!(f, "invalid threshold-raccoon profile"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidShareCount => write!(f, "invalid share count"),
            Self::InvalidSignerSet => write!(f, "invalid signer set"),
            Self::InvalidIndex { index } => write!(f, "invalid index {index}"),
            Self::Encoding => write!(f, "share/commitment/signature encoding error"),
            Self::SignExhausted => write!(f, "signing exhausted its abort budget"),
            Self::WireTruncated => write!(f, "wire payload truncated"),
            Self::BudgetExceeded { actual, budget } => {
                write!(f, "wire payload exceeds budget: {actual} > {budget}")
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
            Self::LengthOverflow => write!(f, "length conversion overflow"),
        }
    }
}

impl std::error::Error for RaccoonError {}
