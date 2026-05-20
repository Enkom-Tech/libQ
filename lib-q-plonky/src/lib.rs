//! Entry point for the full Plonky3-derived STARK implementation in lib-Q.
//!
//! This crate re-exports: univariate STARK (`uni-stark`), batch STARK (`batch-stark`),
//! Keccak AIR (`keccak-air`), lookup arguments (`lookup`), and multilinear utilities
//! (`multilinear-util`). Each is a full implementation; components are enabled via
//! **features** (optional to enable, not optional in completeness).
//!
//! Use the `full` feature to enable the complete set. All dependencies are built on
//! the lib-q-stark-* primitives (NIST, SHAKE256).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "batch-stark")]
pub use lib_q_plonky_batch_stark as batch_stark;
#[cfg(feature = "keccak-air")]
pub use lib_q_plonky_keccak_air as keccak_air;
#[cfg(feature = "lookup")]
pub use lib_q_plonky_lookup as lookup;
#[cfg(feature = "multilinear-util")]
pub use lib_q_plonky_multilinear_util as multilinear_util;
#[cfg(feature = "uni-stark")]
pub use lib_q_plonky_uni_stark as uni_stark;

#[cfg(feature = "wasm")]
pub mod wasm;
