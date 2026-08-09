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
//! ## Parameter sets and the "Top Gun" degree-annihilation attacks (2026-08-09)
//!
//! This crate ships three parameter sets: **Poseidon-128** (original Poseidon,
//! `GF(p²)` over Mersenne31, t=5, alpha=5, R_F=8, R_P=56), **Poseidon-256** (same
//! field, t=7, alpha=5, R_F=8, R_P=60), and **Poseidon2-BabyBear** (the
//! Plonky3/SP1 instance, t=16, alpha=7, R_F=8, R_P=13).
//!
//! Sanso & Vitto, "Top Gun: Degree Annihilation Attacks on Poseidon" (eprint
//! preliminary, 2026), do **not** apply to any of the three sets, each for a
//! reason the paper states in its own words:
//! - Poseidon-128 / Poseidon-256: alpha=5, and the paper says larger exponents
//!   "such as alpha = 5 or alpha = 7 ... increase the local degree that must be
//!   annihilated" and are "expected to make the strategy less effective";
//!   separately, R_F=8 for both sets, and the paper's own R_F=8 experiment
//!   "did not yield a solution, suggesting that this direction should be
//!   revisited with different families of controls".
//! - Poseidon2-BabyBear: it is Poseidon2, and the paper states "the initial
//!   linear transformation prevents the same two-round skip" that the attack's
//!   construction is built on; it also uses alpha=7 and R_F=8, the same two
//!   unfavourable conditions as above.
//!
//! Two caveats that matter and must not be dropped:
//! 1. For Poseidon2-BabyBear, the paper's own (prior-work, classical
//!    one-round-skip) degree formula alpha^(R_F+R_P-1) gives 7^20 ≈ 2^56.1,
//!    against a generic CICO-2 cost on BabyBear of roughly 2^62 for the bare
//!    permutation. This is **not** a Top Gun contribution — Top Gun demonstrates
//!    no Poseidon2 annihilation anywhere in the paper. Whether a CICO-2 solve on
//!    the bare permutation reduces to a collision or preimage attack on our
//!    actual construction (a sponge with rate 7 / capacity 9 field elements,
//!    used for Merkle hashing and Fiat-Shamir) is **undetermined** — no such
//!    reduction was written or found. This is not a break; it is an open
//!    question worth tracking, not something to bury.
//! 2. Poseidon-128 and Poseidon-256 are **not** reference Poseidon parameter
//!    sets: their MDS matrices are a locally-built Cauchy construction and
//!    their round constants come from a local SHAKE256 seed string (no
//!    Grain-LFSR, no external provenance — see the WARNING above and
//!    `constants.rs`). Top Gun §4.1 says exactly this category of deployment
//!    needs "parameter by parameter" analysis. That gap pre-dates and is
//!    independent of Top Gun; Top Gun does not create it and does not close it.
//!
//! Five related papers were sought but could not be obtained at assessment
//! time, so their content is not reflected above: Merz & Rodriguez Garcia,
//! "Skipping Class" (ePrint 2026/306) — the actual Poseidon2/Poseidon2b attack
//! paper, and the largest open gap for the Poseidon2-BabyBear set; Zhao,
//! Sanso, Vitto & Ding, "Graeffe-based attacks on Poseidon and NTT lower
//! bounds" (ePrint 2025/1916); Bak et al. (ePrint 2025/2040); Bak et al.
//! (ePrint 2026/150); and a Grassi et al. survey referenced by Top Gun.
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
/// Value-level Poseidon2 permutation over BabyBear (width 16, the deployed
/// Plonky3/SP1 instance). `no_std`/`alloc`-free; used by the Arm B membership AIR.
pub mod poseidon2_baby_bear;
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
