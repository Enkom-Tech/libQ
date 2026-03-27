//! Duplex-sponge AEAD built from Keccak-f[1600] (SHA-3 family permutation).
//!
//! Rate 136 bytes, 256-bit tag, 256-bit key, 128-bit nonce. Associated data is absorbed
//! before plaintext duplex steps; the tag is the first 32 bytes of the outer state after
//! processing.
//!
//! # Security
//!
//! This construction follows the duplex-sponge model (Bertoni et al.). The permutation is
//! NIST-standardized SHA-3 / FIPS 202; this crate defines a **non-standard** AEAD mode on
//! top of it. Use only after independent review for your threat model.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod crypto;
pub mod params;
pub mod simd;
pub mod state;

#[cfg(feature = "alloc")]
mod aead;

#[cfg(feature = "alloc")]
pub use aead::DuplexSpongeAead;
pub use params::{
    KEY_BYTES,
    NONCE_BYTES,
    RATE_BYTES,
    TAG_BYTES,
};
