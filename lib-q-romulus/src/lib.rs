//! Romulus-N and Romulus-M authenticated encryption (Romulus v1.3).
//!
//! # Modes
//!
//! - **Romulus-N** ([`RomulusN`]): nonce-based AEAD. Unique nonces are required for security.
//! - **Romulus-M** ([`RomulusM`]): misuse-resistant AEAD (SIV-style). Reusing a nonce does not
//!   allow forgery; confidentiality impact is bounded by the MRAE goal of the mode.
//!
//! # API
//!
//! The primary interface is RustCrypto [`aead::AeadInPlace`] (and [`aead::AeadCore`]) with
//! 16-byte key, 16-byte nonce, and 16-byte tag. Use [`aead::KeyInit::new`] to build a cipher
//! from a key.
//!
//! Allocating helpers ([`aead::Aead`]) are available when the `alloc` feature is enabled.
//!
//! When `alloc` is enabled, [`RomulusNAead`] and [`RomulusMAead`] implement [`lib_q_core::Aead`]
//! for integration with the lib-Q AEAD registry.
//!
//! # Targets
//!
//! The cryptographic core is `#![no_std]`, avoids OS services and RNG, and is intended to compile
//! for embedded and `wasm32-unknown-unknown` without `wasm-bindgen` in this crate.
//!
//! # Feature flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! *(none)* | `no_std`, in-place AEAD only |
//! | `alloc` | `aead::Aead`, `lib_q_core::Aead` wrappers |
//! | `std` | Standard library (implies `alloc`) |

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod backend;
pub mod romulus_m;
pub mod romulus_n;
mod skinny;

#[cfg(feature = "alloc")]
mod libq_aead;

pub use aead::consts::{
    U0,
    U16,
};
#[cfg(feature = "alloc")]
pub use libq_aead::{
    RomulusMAead,
    RomulusNAead,
};
pub use romulus_m::RomulusM;
pub use romulus_n::RomulusN;

/// Key size as a [`aead::consts`] typenum (128 bits).
pub type KeySize = U16;
/// Nonce size (128 bits).
pub type NonceSize = U16;
/// Tag size (128 bits).
pub type TagSize = U16;
/// Ciphertext expansion for in-place API (tag is detached).
pub type CiphertextOverhead = U0;
