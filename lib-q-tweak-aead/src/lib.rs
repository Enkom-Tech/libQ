//! Tweakable-block CTR AEAD using Keccak-f\[1600\] (SHA-3 permutation).
//!
//! Each 32-byte block uses an independent sponge evaluation (key, nonce, block counter),
//! enabling SIMD-parallel permutation. The tag is derived by absorbing
//! `key ‖ 0x03 ‖ nonce ‖ len(AD) ‖ AD ‖ len(CT) ‖ CT` into a fresh sponge.
//!
//! # Security
//!
//! The permutation is NIST-standardized; this **mode** is a custom construction and
//! requires independent analysis before production use.

#![cfg_attr(
    not(all(target_arch = "x86_64", feature = "simd-avx2")),
    deny(unsafe_code)
)]
#![deny(unused_qualifications)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod block;
pub mod crypto;
pub use crypto::TweakCryptoError;
pub mod params;
pub mod simd;
pub mod sponge;

#[cfg(feature = "alloc")]
mod aead;

#[cfg(feature = "alloc")]
pub use aead::TweakAead;
pub use params::{
    BLOCK_BYTES,
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
};
