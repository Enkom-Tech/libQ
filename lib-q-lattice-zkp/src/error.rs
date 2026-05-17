//! Error types for proving and verification.

/// Prover-side failures (rejection sampling, bounds).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// Rejection sampling exceeded the iteration budget.
    RejectionLimit,
    /// Public parameters are inconsistent (dimensions).
    InvalidParameters,
}

/// Verifier-side failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Dimension mismatch or malformed encoding.
    InvalidFormat,
    /// Cryptographic check failed.
    Rejected,
}
