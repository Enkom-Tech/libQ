//! Error type for the lattice threshold KEM.

use core::fmt;

/// Errors returned by the lattice threshold KEM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThresholdKemError {
    /// The supplied profile does not match the frozen `V1` profile.
    InvalidProfile,
    /// `threshold == 0` or `threshold > max_parties`.
    InvalidThreshold,
    /// Party / share count out of range (`0`, `> max_parties`, or `< threshold`).
    InvalidShareCount,
    /// The signer / decapper subset is empty, has duplicates, is smaller than `threshold`, uses a
    /// zero party index, or does not contain the calling share's index.
    InvalidSubset,
    /// A ciphertext failed to decode or is structurally malformed (wrong length, wrong element
    /// count, or non-canonical coefficient). Distinct from [`Self::InvalidCiphertext`] so callers
    /// can log wire/structure faults separately from cryptographic FO⊥ rejections.
    EncodingCiphertext,
    /// A public-key blob failed to decode (wrong length or non-canonical coefficient).
    EncodingPublicKey,
    /// A secret-share blob failed to decode (wrong length or non-canonical coefficient).
    EncodingShare,
    /// A [`crate::PartialDecap`] blob failed to decode (wrong length or non-canonical coefficient) —
    /// e.g. a custodian's masked-partial reply on the wire.
    EncodingPartial,
    /// The zero-sharing seed set is missing a pair required by the subset.
    MissingSeed,
    /// A pairwise seed entry supplied to [`crate::threshold::ZeroShareSeeds::from_pairwise`] is
    /// non-canonical: a zero party index, `i >= j` (entries must be the unordered pair `i < j`), or a
    /// duplicate pair. Rejected up front so `seed(i, j)` lookup is unambiguous and fail-closed.
    InvalidSeedEntry,
    /// A share index appeared twice in a combine.
    DuplicateIndex {
        /// The offending party index.
        index: u8,
    },
    /// The FO⊥ re-encryption check failed: the ciphertext is malformed or mauled (explicit
    /// rejection — no shared secret is released).
    InvalidCiphertext,
    /// The per-key decapsulation budget (`DecapBudget`) is exhausted: no further partial may be
    /// emitted on this key until it is rotated (reshared). Bounds exposure to the malformed-ct
    /// insider probe for untrusted senders; see `THRESHOLD_SECURITY.md` §5–§6.
    BudgetExhausted,
}

impl fmt::Display for ThresholdKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile => write!(f, "invalid threshold KEM profile"),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidShareCount => write!(f, "invalid share count"),
            Self::InvalidSubset => write!(f, "invalid decapper subset"),
            Self::EncodingCiphertext => write!(f, "ciphertext failed to decode or is malformed"),
            Self::EncodingPublicKey => write!(f, "public-key blob failed to decode"),
            Self::EncodingShare => write!(f, "share blob failed to decode"),
            Self::EncodingPartial => write!(f, "partial-decap blob failed to decode"),
            Self::MissingSeed => write!(f, "missing pairwise zero-share seed for subset"),
            Self::InvalidSeedEntry => write!(f, "non-canonical pairwise zero-share seed entry"),
            Self::DuplicateIndex { index } => write!(f, "duplicate share index {index}"),
            Self::InvalidCiphertext => write!(f, "ciphertext failed the FO re-encryption check"),
            Self::BudgetExhausted => {
                write!(f, "per-key decapsulation budget exhausted; rotate key")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ThresholdKemError {}
