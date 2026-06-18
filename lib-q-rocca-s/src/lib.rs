//! # lib-Q Rocca-S — high-throughput AES-based AEAD
//!
//! Rocca-S is an authenticated encryption scheme built on the AES round function,
//! designed for very high throughput on hardware with AES acceleration (targeting
//! 6G-class links). This crate implements the IETF draft variant
//! (`draft-nakano-rocca-s`), matching the reference implementation at
//! <https://github.com/jedisct1/rust-rocca-s>, and exposes it through the
//! [`lib_q_core::Aead`] / [`lib_q_core::AeadDecryptSemantic`] traits used across
//! lib-Q.
//!
//! ## Parameters
//! - **Key**: 256 bits (32 bytes)
//! - **Nonce**: 128 bits (16 bytes) — must be unique per key (nonce-respecting)
//! - **Tag**: 256 bits (32 bytes)
//!
//! The 256-bit tag keeps forgery resistance at ~128 bits under a Grover-style
//! quantum search (a 128-bit tag would drop to ~64 bits).
//!
//! ## Backends
//!
//! The AES round runs on a hardware backend selected at runtime when the `simd`
//! features are enabled and the CPU supports it (x86 AES-NI, ARMv8 AES); otherwise
//! a portable scalar AES round is used. All backends are bit-for-bit equivalent.
//!
//! **Constant-time note:** the scalar fallback uses a table-based S-box and is not
//! constant-time. The hardware backends are constant-time. See `SECURITY.md`.
//!
//! ## Example
//!
//! ```rust
//! use lib_q_rocca_s::{
//!     Aead,
//!     AeadKey,
//!     Nonce,
//!     RoccaSAead,
//! };
//!
//! let aead = RoccaSAead::new();
//! let key = AeadKey::new(vec![0u8; 32]);
//! let nonce = Nonce::new(vec![0u8; 16]);
//!
//! let ciphertext = aead
//!     .encrypt(&key, &nonce, b"secret", Some(b"header"))
//!     .unwrap();
//! let plaintext = aead
//!     .decrypt(&key, &nonce, &ciphertext, Some(b"header"))
//!     .unwrap();
//! assert_eq!(plaintext, b"secret");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod round;
mod simd;
mod state;

#[cfg(all(feature = "aead", feature = "alloc"))]
mod aead;

#[cfg(all(feature = "aead", feature = "alloc"))]
pub use aead::RoccaSAead;
// Re-export the lib-Q AEAD surface so downstream code can `use lib_q_rocca_s::Aead`.
pub use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    Result,
};

/// Key size in bytes (256 bits).
pub const KEY_SIZE: usize = 32;
/// Nonce size in bytes (128 bits).
pub const NONCE_SIZE: usize = 16;
/// Authentication tag size in bytes (256 bits).
pub const TAG_SIZE: usize = 32;

/// Internal backend hooks exposed for cross-backend equivalence testing only.
///
/// Not part of the stable API.
#[doc(hidden)]
pub mod _internals {
    /// Whether a hardware AES backend is active on this build/CPU.
    pub use crate::simd::hardware_backend_active;

    /// Scalar (portable) Rocca-S encryption.
    pub fn scalar_encrypt(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> [u8; 32] {
        crate::state::encrypt(key, nonce, ad, plaintext, out)
    }

    /// Scalar (portable) Rocca-S decryption.
    pub fn scalar_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> [u8; 32] {
        crate::state::decrypt(key, nonce, ad, ciphertext, out)
    }

    /// Dispatched Rocca-S encryption (hardware backend when available).
    pub fn dispatch_encrypt(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> [u8; 32] {
        crate::simd::encrypt(key, nonce, ad, plaintext, out)
    }

    /// Dispatched Rocca-S decryption (hardware backend when available).
    pub fn dispatch_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> [u8; 32] {
        crate::simd::decrypt(key, nonce, ad, ciphertext, out)
    }
}
