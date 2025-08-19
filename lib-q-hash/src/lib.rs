//! lib-Q HASH - Post-quantum Hash Functions
//!
//! This crate provides implementations of post-quantum hash functions.

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

// Re-export external hash implementations (explicit to avoid ambiguity)
pub use lib_q_k12::{KangarooTwelve, KangarooTwelveReader};
pub use lib_q_sha3::{
    Keccak224, Keccak256, Keccak256Full, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, Shake128, Shake128Reader, Shake256, Shake256Reader,
};

// Internal modules
mod cshake;
mod hash_types;
mod internal_block_api;
mod kmac;
mod parallelhash;
mod shake;
mod tuplehash;
mod turbo_shake;
mod utils;

// Re-export internal implementations
pub use cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader};
pub use shake::{
    Shake128 as InternalShake128, Shake128Reader as InternalShake128Reader,
    Shake256 as InternalShake256, Shake256Reader as InternalShake256Reader,
};
pub use turbo_shake::{TurboShake128, TurboShake128Reader, TurboShake256, TurboShake256Reader};
// Re-export SP800-185 implementations
pub use kmac::{Kmac128, Kmac128Reader, Kmac256, Kmac256Reader};
pub use parallelhash::{
    ParallelHash128, ParallelHash128Reader, ParallelHash256, ParallelHash256Reader,
};
pub use tuplehash::{TupleHash128, TupleHash128Reader, TupleHash256, TupleHash256Reader};

// Re-export hash types
pub use crate::hash_types::{
    CShake128Hash, CShake256Hash, KangarooTwelveHash, Keccak224Hash, Keccak256Hash, Keccak384Hash,
    Keccak512Hash, Kmac128Hash, Kmac256Hash, ParallelHash128Hash, ParallelHash256Hash,
    Sha3_224Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash, Shake128Hash, Shake256Hash,
    TupleHash128Hash, TupleHash256Hash,
};

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
    /// KMAC128
    Kmac128,
    /// KMAC256
    Kmac256,
    /// TupleHash128
    TupleHash128,
    /// TupleHash256
    TupleHash256,
    /// ParallelHash128
    ParallelHash128,
    /// ParallelHash256
    ParallelHash256,
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
            HashAlgorithm::Kmac128 => 16,
            HashAlgorithm::Kmac256 => 32,
            HashAlgorithm::TupleHash128 => 16,
            HashAlgorithm::TupleHash256 => 32,
            HashAlgorithm::ParallelHash128 => 16,
            HashAlgorithm::ParallelHash256 => 32,
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
        "keccak512",
        "kmac128",
        "kmac256",
        "tuplehash128",
        "tuplehash256",
        "parallelhash128",
        "parallelhash256"
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
        "kmac128" => Ok(Box::new(Kmac128Hash::new())),
        "kmac256" => Ok(Box::new(Kmac256Hash::new())),
        "tuplehash128" => Ok(Box::new(TupleHash128Hash::new())),
        "tuplehash256" => Ok(Box::new(TupleHash256Hash::new())),
        "parallelhash128" => Ok(Box::new(ParallelHash128Hash::new())),
        "parallelhash256" => Ok(Box::new(ParallelHash256Hash::new())),
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
    fn test_invalid_algorithm_name() {
        let result = create_hash("invalid-algorithm");
        assert!(result.is_err());
    }
}
