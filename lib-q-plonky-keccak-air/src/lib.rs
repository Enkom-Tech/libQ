//! An AIR for the Keccak-f permutation. Assumes the field size is between 2^16 and 2^32.
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! Uses only field arithmetic and STARK composition; no classical-only primitives.
//! ## Constant-Time
//! Use constant-time field operations for secret witness data when applicable.
//! ## Memory and Zeroization
//! Wrap trace data in a zeroizing type (e.g. `SecretWitness` from lib-q-stark) when sensitive.
//! ## Input Validation
//! Field size must be in [2^16, 2^32]; enforced by the embedding used.
//! ## Side-Channel Resistance
//! Avoid branching or table lookups on secret intermediate values.
//! ## Threat Model
//! Assumes quantum adversaries; this AIR proves the Keccak-f permutation only, not a full hash.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod air;
mod columns;
mod constants;
mod generation;
mod round_flags;

pub use air::*;
pub use columns::*;
pub use constants::*;
pub use generation::*;

/// Total number of Keccak-f rounds.
pub const NUM_ROUNDS: usize = 24;

/// Number of Keccak-f rounds minus one.
pub const NUM_ROUNDS_MIN_1: usize = NUM_ROUNDS - 1;

/// Number of bits in each limb used to represent 64-bit words.
const BITS_PER_LIMB: usize = 16;

/// Number of limbs needed to represent a 64-bit word.
///
/// Computed as 64 divided by the number of bits per limb.
pub const U64_LIMBS: usize = 64 / BITS_PER_LIMB;

/// Number of rate bits in Keccak-f.
///
/// In Keccak-f[1600], the "rate" parameter for absorbing and squeezing is 1088 bits.
const RATE_BITS: usize = 1088;

/// Number of limbs needed to represent the rate portion of the state.
///
/// Computed as rate bits divided by bits per limb.
const RATE_LIMBS: usize = RATE_BITS / BITS_PER_LIMB;
