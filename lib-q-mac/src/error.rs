//! Error types for qCW-MAC operations.

/// MAC operation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacError {
    /// Tag length does not match the profile.
    InvalidTagLength,
    /// Key material is malformed.
    InvalidKey,
}
