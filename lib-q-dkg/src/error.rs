//! Error type for the dealerless DKG / lattice VSS flow.

use core::fmt;

/// Errors surfaced by the DKG round functions and wire codecs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DkgError {
    /// Profile identifier or geometry does not match the supported `V1` profile.
    InvalidProfile,
    /// Threshold is zero, exceeds the party count, or exceeds `max_parties`.
    InvalidThreshold,
    /// Party count is zero or exceeds `max_parties`.
    InvalidPartyCount,
    /// A party / dealer index is out of the valid `1..=n` range.
    InvalidParty {
        /// The offending index.
        index: u8,
    },
    /// A recipient index is out of the valid `1..=n` range.
    InvalidRecipient {
        /// The offending index.
        index: u8,
    },
    /// The qualified-contribution set is empty or inconsistent.
    EmptyQualifiedSet,
    /// A Fiat–Shamir proof of correct sharing exhausted its abort budget (vanishingly unlikely).
    ProofExhausted,
    /// Mismatched thresholds / dimensions across contributions being combined.
    Mismatch,
    /// A share opening did not decode to the expected module geometry.
    Encoding,
    /// Wire payload ended before all declared fields were read.
    WireTruncated,
    /// Wire payload exceeded the byte budget for its kind.
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

impl fmt::Display for DkgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile => write!(f, "invalid DKG profile"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidPartyCount => write!(f, "invalid party count"),
            Self::InvalidParty { index } => write!(f, "invalid party index {index}"),
            Self::InvalidRecipient { index } => write!(f, "invalid recipient index {index}"),
            Self::EmptyQualifiedSet => write!(f, "empty qualified set"),
            Self::ProofExhausted => write!(f, "share proof exhausted its abort budget"),
            Self::Mismatch => write!(f, "mismatched contribution dimensions"),
            Self::Encoding => write!(f, "share/commitment encoding error"),
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

#[cfg(feature = "std")]
impl std::error::Error for DkgError {}
