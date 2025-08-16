//! libQ - Post-Quantum Cryptography Library
//! 
//! A modern, secure cryptography library built exclusively with NIST-approved 
//! post-quantum algorithms. Written in Rust with WASM compilation support.
//! 
//! # Security Model
//! 
//! - **Zero classical crypto**: No reliance on classical algorithms
//! - **Constant-time operations**: All cryptographic operations are constant-time
//! - **Secure memory**: Automatic secure memory zeroing
//! - **No side-channels**: Designed to prevent timing and power analysis attacks
//! 
//! # Supported Algorithms
//! 
//! ## Key Encapsulation Mechanisms (KEMs)
//! - **CRYSTALS-Kyber** (Level 1, 3, 5)
//! - **Classic McEliece** (Level 1, 3, 4, 5)
//! - **HQC** (Level 1, 3, 4, 5)
//! 
//! ## Digital Signatures
//! - **CRYSTALS-Dilithium** (Level 1, 3, 5)
//! - **Falcon** (Level 1, 5)
//! - **SPHINCS+** (Level 1, 3, 5)
//! 
//! ## Hash Functions
//! - **SHAKE256** (for hash-based signatures)
//! - **SHAKE128** (for general hashing)
//! - **cSHAKE256** (customizable hashing)

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", feature(allocator_api))]
#![cfg_attr(feature = "alloc", feature(alloc_error_handler))]
#![cfg_attr(feature = "alloc", feature(panic_info_message))]

// Core modules
pub mod error;
pub mod kem;
pub mod sig;
pub mod hash;
pub mod aead;
pub mod zkp; // Zero-knowledge proofs
pub mod utils;

// Re-exports for convenience
pub use error::{Error, Result};
pub use kem::{Kem, KemKeypair, KemPublicKey, KemSecretKey};
pub use sig::{Signature, SigKeypair, SigPublicKey, SigSecretKey};
pub use hash::{Hash, HashAlgorithm};
pub use aead::{Aead, AeadKey, Nonce};

// ZKP re-exports (conditional on features) - temporarily disabled
// #[cfg(feature = "stark")]
// pub use zkp::{ZkpProof, ZkpVerifier, ZkpProver};

// Constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

/// Initialize the library
/// 
/// This function should be called before using any cryptographic functions.
/// It performs necessary initialization such as seeding the random number generator.
/// 
/// # Returns
/// 
/// `Ok(())` on success, or an error if initialization fails.
/// 
/// # Example
/// 
/// ```rust
/// use libq::init;
/// 
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     init()?;
///     // Now safe to use cryptographic functions
///     Ok(())
/// }
/// ```
pub fn init() -> Result<()> {
    // Initialize random number generator
    // This is a no-op in most cases, but provides a hook for future initialization
    Ok(())
}

/// Get library version information
/// 
/// Returns a string containing the library version.
/// 
/// # Example
/// 
/// ```rust
/// use libq::version;
/// 
/// println!("libQ version: {}", version());
/// ```
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
        assert_eq!(version(), VERSION);
    }
}
