//! Errors for PRF evaluation and parameter parsing.

/// Failure modes for Legendre / Gold PRF operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrfError {
    /// `(x + K) ≡ 0 (mod p)` so the Legendre symbol is zero and the degree-1 PRF is undefined at this point.
    ZeroInput,
    /// Key material is invalid (e.g. zero or not reduced modulo `p`).
    InvalidKey,
    /// Parameter set is malformed (e.g. modulus not odd).
    InvalidParam,
}
