//! Plonky3-derived ZK proving components for lib-Q.
//!
//! Optional components (Keccak AIR, lookup arguments, batch STARK, etc.)
//! are enabled via features and re-exported here.

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
