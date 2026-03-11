//! Lookup Arguments for STARKs
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! Lookup protocols compose with STARK; no classical-only assumptions.
//! ## Constant-Time
//! Use constant-time operations for any secret values in lookup expressions.
//! ## Memory and Zeroization
//! Zeroize permutation columns and witness data when they are sensitive.
//! ## Input Validation
//! Callers must ensure lookup column indices and expressions are well-formed.
//! ## Side-Channel Resistance
//! LogUp is information-theoretic; no cryptographic assumptions beyond the field.
//! ## Threat Model
//! Assumes quantum adversaries; security relies on field size and soundness of the AIR.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

extern crate alloc;

pub mod debug_util;
pub mod logup;
pub mod lookup_traits;
mod types;

pub use types::*;
