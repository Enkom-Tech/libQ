#![no_std]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
// Allow clippy warnings in SIMD code - these are performance-critical implementations
// where the warnings don't apply to the specific use case
#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::let_and_return,
    clippy::identity_op,
    clippy::erasing_op
)]

#[cfg(feature = "std")]
extern crate std;

mod arithmetic;
pub mod constants;
mod encoding;
mod hash_functions;
mod helper;
mod matrix;
mod ml_dsa_generic;
mod ntt;
mod polynomial;
mod pre_hash;
pub mod rng;
mod sample;
mod samplex4;
mod sha3_shim;
mod simd;

#[cfg(hax)]
mod specs;

pub mod types;

// Re-export hash functions for derive_message_representative
pub use pre_hash::DomainSeparationContext;
// Public interface
pub use types::*;

pub use crate::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};

#[cfg(feature = "mldsa44")]
pub mod ml_dsa_44;

#[cfg(feature = "mldsa65")]
pub mod ml_dsa_65;

#[cfg(feature = "mldsa87")]
pub mod ml_dsa_87;
