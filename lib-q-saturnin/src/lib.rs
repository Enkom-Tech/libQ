//! # lib-Q Saturnin - Post-Quantum Symmetric Algorithm Suite
//!
//! This crate provides implementations of the Saturnin post-quantum symmetric algorithm suite.
//! Saturnin is designed for IoT and constrained devices, providing authenticated encryption,
//! block cipher, hashing, and stream cipher modes with superior post-quantum security.
//!
//! ## Features
//!
//! - **Post-quantum security**: Designed to resist quantum attacks
//! - **Lightweight**: Optimized for constrained devices and IoT
//! - **Multiple modes**: AEAD, block cipher, hash, and stream cipher
//! - **Memory safe**: Built in Rust with zero-cost abstractions
//! - **No-std support**: Works in embedded environments
//!
//! ## Algorithm Modes
//!
//! - **AEAD**: Authenticated encryption with associated data
//! - **Block Cipher**: 256-bit block cipher
//! - **Hash Function**: Cryptographic hash function
//! - **Stream Cipher**: Stream cipher mode

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_qualifications
)]

#[cfg(not(feature = "alloc"))]
compile_error!(
    "lib-q-saturnin requires the 'alloc' feature to be enabled. This crate cannot function without alloc support."
);

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    vec::Vec,
};

// Re-export core types for public use
pub use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
    Result,
};

// Algorithm implementations
#[cfg(feature = "aead")]
pub mod aead;

// TODO: Implement additional Saturnin modes
// #[cfg(feature = "block-cipher")]
// pub mod block_cipher;

// #[cfg(feature = "hash")]
// pub mod hash;

// #[cfg(feature = "stream")]
// pub mod stream;

// Re-export main implementations
#[cfg(feature = "aead")]
pub use aead::SaturninAead;

// TODO: Re-export additional implementations when modules are created
// #[cfg(feature = "block-cipher")]
// pub use block_cipher::SaturninBlockCipher;

// #[cfg(feature = "hash")]
// pub use hash::SaturninHash;

// #[cfg(feature = "stream")]
// pub use stream::SaturninStream;

/// Get available Saturnin algorithm modes
#[allow(clippy::vec_init_then_push)] // Can't use vec![] due to feature-gated content
pub fn available_modes() -> Vec<&'static str> {
    let mut modes = Vec::new();

    #[cfg(feature = "aead")]
    modes.push("aead");

    // TODO: Add other modes when implemented
    // #[cfg(feature = "block-cipher")]
    // modes.push("block-cipher");

    // #[cfg(feature = "hash")]
    // modes.push("hash");

    // #[cfg(feature = "stream")]
    // modes.push("stream");

    modes
}

/// Create a Saturnin instance by mode name
pub fn create_saturnin(mode: &str) -> Result<Box<dyn Aead>> {
    match mode {
        #[cfg(feature = "aead")]
        "aead" => Ok(Box::new(SaturninAead::new())),
        _ => Err(Error::InvalidAlgorithm {
            algorithm: "Unknown Saturnin mode",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_modes() {
        let modes = available_modes();
        assert!(!modes.is_empty());
    }

    #[test]
    fn test_create_saturnin() {
        #[cfg(feature = "aead")]
        {
            let aead = create_saturnin("aead");
            assert!(aead.is_ok());
        }

        let invalid = create_saturnin("invalid");
        assert!(invalid.is_err());
    }
}
