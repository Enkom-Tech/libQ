//! Error type.

use core::fmt;

/// Errors returned by this crate.
///
/// Deliberately short. `dDecaps` does not fail on a malformed ciphertext — CK-FO's implicit
/// rejection returns a pseudorandom key instead — so the only error is a structural one that no
/// amount of adversarial input can trigger on a correctly-sized wire message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaulError {
    /// The ciphertext is not the length this parameter set requires.
    CiphertextLength {
        /// Length the parameter set requires.
        expected: usize,
        /// Length supplied.
        got: usize,
    },
}

impl fmt::Display for MaulError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextLength { expected, got } => {
                write!(f, "ciphertext length {got}, expected {expected}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MaulError {}
