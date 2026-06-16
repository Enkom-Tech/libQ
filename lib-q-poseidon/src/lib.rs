//! Poseidon hash function optimized for zero-knowledge proofs
//!
//! This crate provides a field-native implementation of the Poseidon hash function,
//! specifically optimized for use in STARK proof systems with `Complex<Mersenne31>`.
//!
//! # Design
//!
//! Poseidon is an algebraic hash function designed for efficient implementation in
//! zero-knowledge proof systems. Unlike traditional hashes like SHA-3, Poseidon
//! operates directly on field elements, making it orders of magnitude more efficient
//! in circuit constraints.
//!
//! # Security
//!
//! - Uses round counts and an MDS construction inspired by the Poseidon design.
//! - MDS matrices use a Cauchy construction (every square submatrix is invertible).
//!
//! WARNING: the round counts and sponge parameters in this crate have NOT been
//! independently verified for the `Complex<Mersenne31>` extension field GF(p²).
//! The standard Poseidon security analysis is stated over a prime field and does
//! not directly cover this exact field and state. Do NOT rely on a specific
//! bit-security level (e.g. 128-bit or 256-bit) for these parameters until they
//! have been regenerated and analyzed for GF(p²).
//!
//! # Example
//!
//! ```rust,ignore
//! use lib_q_poseidon::{Poseidon, Poseidon128};
//! use lib_q_stark_field::extension::Complex;
//! use lib_q_stark_mersenne31::Mersenne31;
//!
//! type Val = Complex<Mersenne31>;
//!
//! let hasher = Poseidon128::permutation();
//! let input = vec![Val::from(1u32), Val::from(2u32)];
//! let hash = hasher.hash(&input);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(all(feature = "alloc", feature = "std"))]
use alloc::string::ToString;

mod constants;
#[cfg(feature = "alloc")]
mod params;
#[cfg(feature = "alloc")]
mod permutation;
#[cfg(feature = "alloc")]
mod sponge;

// Export constants for AIR constraint generation
pub use constants::sbox;
#[cfg(feature = "alloc")]
pub use constants::{
    mds_matrix_5x5,
    mds_matrix_7x7,
};
#[cfg(feature = "alloc")]
pub use constants::{
    round_constants_128,
    round_constants_256,
};
#[cfg(feature = "alloc")]
pub use params::{
    Poseidon128,
    Poseidon256,
    PoseidonField,
    PoseidonParams,
};
#[cfg(feature = "alloc")]
pub use permutation::{
    PoseidonPermutation,
    PoseidonState,
};
#[cfg(feature = "alloc")]
pub use sponge::{
    Poseidon,
    PoseidonSponge,
    PoseidonSpongeSqueeze,
};

#[cfg(feature = "wasm")]
pub mod wasm;

/// Error types for Poseidon operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoseidonError {
    /// Input size exceeds maximum allowed
    InputTooLarge { max: usize, actual: usize },
    /// Invalid parameter configuration
    #[cfg(feature = "alloc")]
    InvalidParams { reason: String },
    /// Internal error during hashing
    #[cfg(feature = "alloc")]
    InternalError { reason: String },
}

impl core::fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PoseidonError::InputTooLarge { max, actual } => {
                write!(f, "Input size {} exceeds maximum {}", actual, max)
            }
            #[cfg(feature = "alloc")]
            PoseidonError::InvalidParams { reason } => {
                write!(f, "Invalid Poseidon parameters: {}", reason)
            }
            #[cfg(feature = "alloc")]
            PoseidonError::InternalError { reason } => {
                write!(f, "Internal Poseidon error: {}", reason)
            }
        }
    }
}

#[cfg(all(feature = "alloc", feature = "std"))]
impl From<PoseidonError> for lib_q_core::Error {
    fn from(err: PoseidonError) -> Self {
        lib_q_core::Error::InternalError {
            operation: "Poseidon hash".into(),
            details: err.to_string(),
        }
    }
}

#[cfg(all(not(feature = "alloc"), feature = "std"))]
impl From<PoseidonError> for lib_q_core::Error {
    fn from(err: PoseidonError) -> Self {
        match err {
            PoseidonError::InputTooLarge { .. } => lib_q_core::Error::InternalError {
                operation: "Poseidon hash",
                details: "input too large",
            },
        }
    }
}
