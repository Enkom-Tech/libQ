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
//!
//! ## Usage Examples
//!
//! ### AEAD (Authenticated Encryption)
//! ```rust
//! #[cfg(feature = "aead")]
//! fn main() {
//!     use lib_q_saturnin::{
//!         Aead,
//!         AeadKey,
//!         Nonce,
//!         SaturninAead,
//!     };
//!
//!     let aead = SaturninAead::new();
//!     let key = AeadKey::new(vec![0u8; 32]);
//!     let nonce = Nonce::new(vec![0u8; 16]);
//!     let plaintext = b"Hello, World!";
//!     let associated_data = b"metadata";
//!
//!     let ciphertext = aead
//!         .encrypt(&key, &nonce, plaintext, Some(associated_data))
//!         .unwrap();
//!
//!     let decrypted = aead
//!         .decrypt(&key, &nonce, &ciphertext, Some(associated_data))
//!         .unwrap();
//!     assert_eq!(decrypted, plaintext);
//! }
//! #[cfg(not(feature = "aead"))]
//! fn main() {}
//! ```
//!
//! ### Hash Function
//! ```rust
//! #[cfg(feature = "hash")]
//! fn main() {
//!     use lib_q_saturnin::SaturninHash;
//!
//!     let hash = SaturninHash::new();
//!     let data = b"Hello, World!";
//!
//!     let hash_output = hash.hash(data).unwrap();
//!     assert_eq!(hash_output.len(), 32); // 256-bit output
//! }
//! #[cfg(not(feature = "hash"))]
//! fn main() {}
//! ```
//!
//! ### Block Cipher
//! ```rust
//! #[cfg(feature = "block-cipher")]
//! fn main() {
//!     use lib_q_saturnin::SaturninBlockCipher;
//!
//!     let cipher = SaturninBlockCipher::new();
//!     let key = vec![0u8; 32];
//!     let block = vec![0u8; 32];
//!
//!     let encrypted = cipher.encrypt_block(&key, &block).unwrap();
//!     let decrypted = cipher.decrypt_block(&key, &encrypted).unwrap();
//!     assert_eq!(decrypted, block);
//! }
//! #[cfg(not(feature = "block-cipher"))]
//! fn main() {}
//! ```
//!
//! ### Stream Cipher
//! ```rust
//! #[cfg(feature = "stream")]
//! fn main() {
//!     use lib_q_saturnin::SaturninStream;
//!
//!     let stream = SaturninStream::new();
//!     let key = vec![0u8; 32];
//!     let nonce = vec![0u8; 16];
//!     let plaintext = b"Hello, World!";
//!
//!     let ciphertext = stream.encrypt(&key, &nonce, plaintext).unwrap();
//!     let decrypted = stream.decrypt(&key, &nonce, &ciphertext).unwrap();
//!     assert_eq!(decrypted, plaintext);
//! }
//! #[cfg(not(feature = "stream"))]
//! fn main() {}
//! ```
//!
//! ## Performance Characteristics
//!
//! Saturnin is optimized for constrained devices and IoT applications:
//! - **Lightweight**: Minimal memory footprint
//! - **Fast**: Optimized for 32-bit and 64-bit processors
//! - **Efficient**: Bitsliced implementation for speed
//! - **Scalable**: Performance scales well with data size
//!
//! Typical performance on modern hardware:
//! - **AEAD**: ~100-500 MB/s depending on data size
//! - **Hash**: ~200-800 MB/s depending on data size
//! - **Block Cipher**: ~50-200 MB/s for single blocks
//! - **Stream Cipher**: ~100-400 MB/s depending on data size
//!
//! ## Security Properties
//!
//! Saturnin provides post-quantum security through:
//! - **Resistance to quantum attacks**: Designed to resist Shor's and Grover's algorithms
//! - **AES-like security**: 256-bit security level
//! - **Authenticated encryption**: Built-in integrity protection
//! - **Provable security**: Based on well-studied cryptographic primitives
//! - **Lightweight design**: Suitable for constrained environments

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code, unused_must_use, unstable_features)]
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
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    Result,
};

// Core implementation
pub mod bs32_core;
pub mod core;

// Performance optimizations
#[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
pub mod parallel;
#[cfg(any(feature = "simd", feature = "simd-avx2", feature = "simd-neon"))]
#[allow(unsafe_code)]
pub mod simd;

// Algorithm implementations
#[cfg(feature = "aead")]
pub mod aead;

#[cfg(feature = "aead-short")]
pub mod aead_short;

#[cfg(feature = "block-cipher")]
pub mod block_cipher;

#[cfg(feature = "hash")]
pub mod hash;

#[cfg(feature = "stream")]
pub mod stream;

// Re-export main implementations
#[cfg(feature = "aead")]
pub use aead::SaturninAead;
#[cfg(feature = "aead-short")]
pub use aead_short::SaturninShortAead;
#[cfg(feature = "block-cipher")]
pub use block_cipher::SaturninBlockCipher;
#[cfg(feature = "hash")]
pub use hash::SaturninHash;
#[cfg(feature = "stream")]
pub use stream::{
    SaturninKeystream,
    SaturninStream,
};

/// Get available Saturnin algorithm modes
#[allow(clippy::vec_init_then_push, unused_mut)] // Can't use vec![] due to feature-gated content
pub fn available_modes() -> Vec<&'static str> {
    let mut modes = Vec::new();

    #[cfg(feature = "aead")]
    modes.push("aead");

    #[cfg(feature = "aead-short")]
    modes.push("aead-short");

    #[cfg(feature = "block-cipher")]
    modes.push("block-cipher");

    #[cfg(feature = "hash")]
    modes.push("hash");

    #[cfg(feature = "stream")]
    modes.push("stream");

    modes
}

/// Create a Saturnin instance by mode name
pub fn create_saturnin(mode: &str) -> Result<Box<dyn Aead>> {
    match mode {
        #[cfg(feature = "aead")]
        "aead" => Ok(Box::new(SaturninAead::new())),
        #[cfg(feature = "aead-short")]
        "aead-short" => Ok(Box::new(SaturninShortAead::new())),
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
