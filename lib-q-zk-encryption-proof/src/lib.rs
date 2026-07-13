//! ZK-STARK proof of correct encryption (proof-of-knowledge of message `mu`)
//! for [`lib-q-threshold-kem-lattice`] ciphertexts.
//!
//! **Status: RED/unsigned — research add-on, not reviewed, not production-ready.**
//!
//! Design document:
//! `dev/conformance/integration/lib-q-threshold-kem-lattice/ENCRYPTION_PROOF_DESIGN.md`
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
//! All ciphertext components must be validated before passing to the prover.
//! ## Side-Channel Resistance
//! Avoid branching or table lookups on secret intermediate values.
//! ## Threat Model
//! Assumes quantum adversaries; this module proves knowledge of `mu` only, not full protocol security.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

extern crate alloc;

pub mod air;
pub mod compose;
pub mod error;
pub mod gate;
pub mod logup_join;
pub mod prove;
pub mod relation_assembly;
pub mod sampler;
pub mod sponge;
pub mod sponge_air;
pub mod squeeze_byte;
pub mod zq;

#[cfg(test)]
mod fuzz;
