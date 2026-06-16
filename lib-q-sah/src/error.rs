//! Error type for S-A-H operations.

use core::fmt;

/// Errors returned by S-A-H seal/open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SahError {
    /// Authentication failed: the tag did not verify, or the input was shorter
    /// than the tag. Plaintext output (if any) has been zeroized. The two cases
    /// are deliberately indistinguishable so the API exposes no
    /// malformed-vs-forged oracle.
    AuthenticationFailed,
    /// An input length exceeds the supported maximum, or a key/nonce slice had
    /// the wrong length.
    InvalidLength,
}

impl fmt::Display for SahError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SahError::AuthenticationFailed => f.write_str("S-A-H authentication failed"),
            SahError::InvalidLength => f.write_str("S-A-H invalid input length"),
        }
    }
}

impl core::error::Error for SahError {}
