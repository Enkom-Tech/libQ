//! # lib-q-mayo
//!
//! MAYO multivariate signature scheme, NIST additional-signatures **round 2**,
//! MAYO_2 parameter set (security level 1): 4912-byte verification keys,
//! 186-byte fixed-length signatures, 24-byte seed-based signing keys.
//!
//! Hand-written from the round-2 specification and cross-checked against the
//! authors' reference implementation and the official round-2 KAT vectors
//! (`PQCsignKAT_24_MAYO_2.rsp`).
//!
//! ## Status
//!
//! **Experimental / pre-standard.** MAYO is a round-2 candidate in NIST's
//! additional-signatures process, not a finished standard. Parameters may
//! still change; downstream protocols should version their suite identifiers
//! accordingly.
//!
//! ## Constant-time posture
//!
//! Integer-only arithmetic (no lookup tables), no secret-dependent branches
//! or memory indices in signing. The linear-system solve uses the reference
//! implementation's constant-time echelon form; the only secret-derived
//! branch is the public "restart" predicate of the retry loop, identical to
//! the reference implementation's declassification. Secret buffers are wiped
//! on drop (feature `zeroize` uses the `zeroize` crate; without it a
//! volatile-write fallback is used).
//!
//! ## Example
//!
//! ```
//! use lib_q_mayo::mayo_2;
//!
//! let keypair = mayo_2::generate_key_pair([1u8; 24]);
//! let signature =
//!     mayo_2::sign(&keypair.signing_key, b"message", [2u8; 24]).unwrap();
//! assert!(
//!     mayo_2::verify(&keypair.verification_key, b"message", &signature)
//!         .is_ok()
//! );
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::all)]

mod expand;
mod gf16;
mod mayo_core;
mod mvec;
mod params;
mod types;

#[cfg(feature = "mayo2")]
pub mod mayo_2;

pub use types::{
    DecodeError,
    Mayo2KeyPair,
    Mayo2Signature,
    Mayo2SigningKey,
    Mayo2VerificationKey,
};

/// Errors that can occur during signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// No solvable linear system was found within the 256-iteration retry
    /// budget (probability ~2^-256; in practice indicates corrupted state).
    RetryLimitExceeded,
}

/// Errors that can occur during verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    /// The signature is not valid for this message and verification key.
    VerificationFailed,
}

impl core::fmt::Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigningError::RetryLimitExceeded => f.write_str("retry limit exceeded"),
        }
    }
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerificationError::VerificationFailed => f.write_str("verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigningError {}
#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
