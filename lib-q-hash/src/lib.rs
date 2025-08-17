//! lib-Q HASH - Post-quantum Hash Functions
//!
//! This crate provides implementations of post-quantum hash functions based on SHA-3.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

use alloc::{boxed::Box, string::ToString, vec::Vec};

// Re-export core types for public use
pub use lib_q_core::{Algorithm, Hash, HashContext, Result};

// Re-export digest traits for internal use
pub use digest::{
    self, CollisionResistance, CustomizedInit, Digest, ExtendableOutput, ExtendableOutputReset,
    Update,
};

// Block-level types and core implementation
/// Block-level API for hash functions
pub mod block_api;
mod cshake;
mod k12;
mod sha3;
mod shake;
mod turbo_shake;

// Constants for SHA-3 implementation
/// Length of the Keccak state array
pub const PLEN: usize = 25;
/// Default number of rounds for Keccak permutation
pub const DEFAULT_ROUND_COUNT: usize = 24;

// Paddings
/// Keccak padding value
pub const KECCAK_PAD: u8 = 0x01;
/// SHA-3 padding value
pub const SHA3_PAD: u8 = 0x06;
/// SHAKE padding value
pub const SHAKE_PAD: u8 = 0x1f;
/// cSHAKE padding value
pub const CSHAKE_PAD: u8 = 0x04;

// Re-export the SHA-3 implementations
pub use cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader};
pub use k12::{KangarooTwelve, KangarooTwelveReader};
pub use sha3::{
    Keccak224, Keccak256, Keccak256Full, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512,
};
pub use shake::{Shake128, Shake128Reader, Shake256, Shake256Reader};
pub use turbo_shake::{TurboShake128, TurboShake128Reader, TurboShake256, TurboShake256Reader};

// Re-export hash types
pub use crate::hash_types::{
    CShake128Hash, CShake256Hash, KangarooTwelveHash, Keccak224Hash, Keccak256Hash, Keccak384Hash,
    Keccak512Hash, Sha3_224Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash, Shake128Hash,
    Shake256Hash,
};

// Hash type implementations
mod hash_types;

/// Hash algorithm types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-3-224
    Sha3_224,
    /// SHA-3-256
    Sha3_256,
    /// SHA-3-384
    Sha3_384,
    /// SHA-3-512
    Sha3_512,
    /// SHAKE128
    Shake128,
    /// SHAKE256
    Shake256,
    /// cSHAKE128
    CShake128,
    /// cSHAKE256
    CShake256,
    /// KangarooTwelve
    KangarooTwelve,
    /// Keccak-224
    Keccak224,
    /// Keccak-256
    Keccak256,
    /// Keccak-384
    Keccak384,
    /// Keccak-512
    Keccak512,
}

impl HashAlgorithm {
    /// Get the output size for this algorithm
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha3_224 => 28,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha3_512 => 64,
            HashAlgorithm::Shake128 => 16,
            HashAlgorithm::Shake256 => 32,
            HashAlgorithm::CShake128 => 16,
            HashAlgorithm::CShake256 => 32,
            HashAlgorithm::KangarooTwelve => 32, // Default output size
            HashAlgorithm::Keccak224 => 28,
            HashAlgorithm::Keccak256 => 32,
            HashAlgorithm::Keccak384 => 48,
            HashAlgorithm::Keccak512 => 64,
        }
    }
}

/// Get available hash algorithms
pub fn available_algorithms() -> Vec<&'static str> {
    alloc::vec![
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "shake128",
        "shake256",
        "cshake128",
        "cshake256",
        "kangarootwelve",
        "keccak224",
        "keccak256",
        "keccak384",
        "keccak512"
    ]
}

/// Create a hash instance by algorithm name
pub fn create_hash(algorithm: &str) -> Result<Box<dyn Hash>> {
    match algorithm {
        "sha3-224" => Ok(Box::new(Sha3_224Hash::new())),
        "sha3-256" => Ok(Box::new(Sha3_256Hash::new())),
        "sha3-384" => Ok(Box::new(Sha3_384Hash::new())),
        "sha3-512" => Ok(Box::new(Sha3_512Hash::new())),
        "shake128" => Ok(Box::new(Shake128Hash::new())),
        "shake256" => Ok(Box::new(Shake256Hash::new())),
        "cshake128" => Ok(Box::new(CShake128Hash::new())),
        "cshake256" => Ok(Box::new(CShake256Hash::new())),
        "kangarootwelve" => Ok(Box::new(KangarooTwelveHash::new())),
        "keccak224" => Ok(Box::new(Keccak224Hash::new())),
        "keccak256" => Ok(Box::new(Keccak256Hash::new())),
        "keccak384" => Ok(Box::new(Keccak384Hash::new())),
        "keccak512" => Ok(Box::new(Keccak512Hash::new())),
        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

/// Create a hash context for the specified algorithm
pub fn create_hash_context(algorithm: Algorithm) -> Result<HashContext> {
    // Validate that this is a hash algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Hash {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: alloc::format!("{algorithm:?} is not a hash algorithm"),
        });
    }

    Ok(HashContext::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        assert!(!algorithms.is_empty());
        assert!(algorithms.contains(&"sha3-224"));
        assert!(algorithms.contains(&"sha3-256"));
        assert!(algorithms.contains(&"sha3-384"));
        assert!(algorithms.contains(&"sha3-512"));
        assert!(algorithms.contains(&"shake128"));
        assert!(algorithms.contains(&"shake256"));
        assert!(algorithms.contains(&"cshake256"));
        assert!(algorithms.contains(&"kangarootwelve"));
        assert!(algorithms.contains(&"keccak224"));
        assert!(algorithms.contains(&"keccak256"));
        assert!(algorithms.contains(&"keccak384"));
        assert!(algorithms.contains(&"keccak512"));
    }

    #[test]
    fn test_hash_algorithm_output_sizes() {
        assert_eq!(HashAlgorithm::Sha3_224.output_size(), 28);
        assert_eq!(HashAlgorithm::Sha3_256.output_size(), 32);
        assert_eq!(HashAlgorithm::Sha3_384.output_size(), 48);
        assert_eq!(HashAlgorithm::Sha3_512.output_size(), 64);
        assert_eq!(HashAlgorithm::Shake128.output_size(), 16);
        assert_eq!(HashAlgorithm::Shake256.output_size(), 32);
        assert_eq!(HashAlgorithm::CShake128.output_size(), 16);
        assert_eq!(HashAlgorithm::CShake256.output_size(), 32);
        assert_eq!(HashAlgorithm::KangarooTwelve.output_size(), 32);
        assert_eq!(HashAlgorithm::Keccak224.output_size(), 28);
        assert_eq!(HashAlgorithm::Keccak256.output_size(), 32);
        assert_eq!(HashAlgorithm::Keccak384.output_size(), 48);
        assert_eq!(HashAlgorithm::Keccak512.output_size(), 64);
    }

    #[test]
    fn test_create_hash_context() {
        let mut ctx = create_hash_context(Algorithm::Shake256).unwrap();
        // Context is created successfully
        assert!(ctx.hash(Algorithm::Shake256, b"test").is_ok());
    }

    #[test]
    fn test_create_hash_context_invalid_algorithm() {
        let result = create_hash_context(Algorithm::Kyber512);
        assert!(result.is_err());
    }

    #[test]
    fn test_sha3_implementations() {
        // Test SHA3-224
        let sha3_224 = Sha3_224Hash::new();
        let result = sha3_224.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 28);

        // Test SHA3-256
        let sha3_256 = Sha3_256Hash::new();
        let result = sha3_256.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);

        // Test SHA3-384
        let sha3_384 = Sha3_384Hash::new();
        let result = sha3_384.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 48);

        // Test SHA3-512
        let sha3_512 = Sha3_512Hash::new();
        let result = sha3_512.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_cshake_implementations() {
        // Test cSHAKE256
        let cshake = CShake256Hash::new();
        let result = cshake.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_cshake_customization() {
        // Test that different customizations produce different outputs
        let cshake1 = CShake256Hash::new_customized(b"App1");
        let cshake2 = CShake256Hash::new_customized(b"App2");

        let hash1 = cshake1.hash(b"test").unwrap();
        let hash2 = cshake2.hash(b"test").unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_shake_implementations() {
        // Test SHAKE128
        let shake128 = Shake128Hash::new();
        let result = shake128.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 16);

        // Test SHAKE256
        let shake256 = Shake256Hash::new();
        let result = shake256.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_k12_implementations() {
        // Test KangarooTwelve
        let k12 = KangarooTwelveHash::new();
        let result = k12.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);

        // Test KangarooTwelve with customization
        let k12_custom = KangarooTwelveHash::new_customized(b"custom");
        let result = k12_custom.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_keccak_implementations() {
        // Test Keccak-224
        let keccak224 = Keccak224Hash::new();
        let result = keccak224.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 28);

        // Test Keccak-256
        let keccak256 = Keccak256Hash::new();
        let result = keccak256.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 32);

        // Test Keccak-384
        let keccak384 = Keccak384Hash::new();
        let result = keccak384.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 48);

        // Test Keccak-512
        let keccak512 = Keccak512Hash::new();
        let result = keccak512.hash(b"Hello, World!").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_create_hash_by_name() {
        let sha3_224 = create_hash("sha3-224").unwrap();
        let result = sha3_224.hash(b"test").unwrap();
        assert_eq!(result.len(), 28);

        let sha3_256 = create_hash("sha3-256").unwrap();
        let result = sha3_256.hash(b"test").unwrap();
        assert_eq!(result.len(), 32);

        let sha3_384 = create_hash("sha3-384").unwrap();
        let result = sha3_384.hash(b"test").unwrap();
        assert_eq!(result.len(), 48);

        let sha3_512 = create_hash("sha3-512").unwrap();
        let result = sha3_512.hash(b"test").unwrap();
        assert_eq!(result.len(), 64);

        let shake128 = create_hash("shake128").unwrap();
        let result = shake128.hash(b"test").unwrap();
        assert_eq!(result.len(), 16);

        let shake256 = create_hash("shake256").unwrap();
        let result = shake256.hash(b"test").unwrap();
        assert_eq!(result.len(), 32);

        let cshake256 = create_hash("cshake256").unwrap();
        let result = cshake256.hash(b"test").unwrap();
        assert_eq!(result.len(), 32);

        let kangarootwelve = create_hash("kangarootwelve").unwrap();
        let result = kangarootwelve.hash(b"test").unwrap();
        assert_eq!(result.len(), 32);

        let keccak224 = create_hash("keccak224").unwrap();
        let result = keccak224.hash(b"test").unwrap();
        assert_eq!(result.len(), 28);

        let keccak256 = create_hash("keccak256").unwrap();
        let result = keccak256.hash(b"test").unwrap();
        assert_eq!(result.len(), 32);

        let keccak384 = create_hash("keccak384").unwrap();
        let result = keccak384.hash(b"test").unwrap();
        assert_eq!(result.len(), 48);

        let keccak512 = create_hash("keccak512").unwrap();
        let result = keccak512.hash(b"test").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_invalid_algorithm_name() {
        let result = create_hash("invalid-algorithm");
        assert!(result.is_err());
    }
}
