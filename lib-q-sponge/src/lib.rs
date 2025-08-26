//! lib-Q Sponge - Sponge Functions for lib-Q
//!
//! This crate provides sponge functions including Keccak for use in lib-Q.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

// Re-export keccak functions
// Re-export ascon functions
pub use lib_q_ascon::*;
pub use lib_q_keccak::*;
