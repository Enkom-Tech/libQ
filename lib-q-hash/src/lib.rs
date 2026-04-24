//! lib-Q HASH - Post-quantum Hash Functions
//!
//! This crate provides implementations of post-quantum hash functions.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

// Re-export digest traits for internal use
pub use digest::{
    self,
    CollisionResistance,
    CustomizedInit,
    Digest,
    ExtendableOutput,
    ExtendableOutputReset,
    Update,
};
// Re-export core types for public use
pub use lib_q_core::{
    Algorithm,
    Hash,
    HashContext,
    Result,
};
// Re-export external hash implementations (explicit to avoid ambiguity)
pub use lib_q_k12::{
    Kt128,
    Kt128Reader,
    Kt256,
    Kt256Reader,
};
pub use lib_q_keccak_digest::{
    Keccak224,
    Keccak256,
    Keccak256Full,
    Keccak384,
    Keccak512,
};
pub use lib_q_sha3::{
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake128Reader,
    Shake256,
    Shake256Reader,
};

// Internal modules
mod cshake;
mod hash_types;
mod internal_block_api;
mod kmac;
mod parallelhash;
#[cfg(feature = "alloc")]
mod provider;
mod sha2_hashes;
mod shake;
mod tuplehash;
mod turbo_shake;
mod utils;

// Re-export internal implementations
pub use cshake::{
    CShake128,
    CShake128Reader,
    CShake256,
    CShake256Reader,
};
// Re-export SP800-185 implementations
pub use kmac::{
    Kmac128,
    Kmac128Reader,
    Kmac256,
    Kmac256Reader,
};
pub use parallelhash::{
    ParallelHash128,
    ParallelHash128Reader,
    ParallelHash256,
    ParallelHash256Reader,
};
// Re-export provider
#[cfg(feature = "alloc")]
pub use provider::LibQHashProvider;
pub use sha2_hashes::{
    Sha224Hash,
    Sha256Hash,
    Sha384Hash,
    Sha512_224Hash,
    Sha512_256Hash,
    Sha512Hash,
};
pub use shake::{
    Shake128 as InternalShake128,
    Shake128Reader as InternalShake128Reader,
    Shake256 as InternalShake256,
    Shake256Reader as InternalShake256Reader,
};
pub use tuplehash::{
    TupleHash128,
    TupleHash128Reader,
    TupleHash256,
    TupleHash256Reader,
};
pub use turbo_shake::{
    TurboShake128,
    TurboShake128Reader,
    TurboShake256,
    TurboShake256Reader,
};

// Re-export hash types
pub use crate::hash_types::{
    CShake128Hash,
    CShake256Hash,
    Keccak224Hash,
    Keccak256Hash,
    Keccak384Hash,
    Keccak512Hash,
    Kmac128Hash,
    Kmac256Hash,
    Kt128Hash,
    Kt256Hash,
    ParallelHash128Hash,
    ParallelHash256Hash,
    Sha3_224Hash,
    Sha3_256Hash,
    Sha3_384Hash,
    Sha3_512Hash,
    Shake128Hash,
    Shake256Hash,
    TupleHash128Hash,
    TupleHash256Hash,
    TurboShake128Hash,
    TurboShake256Hash,
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
pub const SHAKE_PAD: u8 = 0x1F;
/// cSHAKE padding value
pub const CSHAKE_PAD: u8 = 0x04;

/// Hash algorithm types that map to lib-q-core Algorithm enum
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
    Cshake128,
    /// cSHAKE256
    Cshake256,
    /// KT128 (KangarooTwelve with TurboSHAKE128)
    Kt128,
    /// KT256 (KangarooTwelve with TurboSHAKE256)
    Kt256,
    /// Keccak-224
    Keccak224,
    /// Keccak-256
    Keccak256,
    /// Keccak-384
    Keccak384,
    /// Keccak-512
    Keccak512,
    /// TurboShake128
    TurboShake128,
    /// TurboShake256
    TurboShake256,
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
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA-512/224
    Sha512_224,
    /// SHA-512/256
    Sha512_256,
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
            HashAlgorithm::Cshake128 => 16,
            HashAlgorithm::Cshake256 => 32,
            HashAlgorithm::Kt128 => 32,
            HashAlgorithm::Kt256 => 64,
            HashAlgorithm::Keccak224 => 28,
            HashAlgorithm::Keccak256 => 32,
            HashAlgorithm::Keccak384 => 48,
            HashAlgorithm::Keccak512 => 64,
            HashAlgorithm::TurboShake128 => 16,
            HashAlgorithm::TurboShake256 => 32,
            HashAlgorithm::Kmac128 => 16,
            HashAlgorithm::Kmac256 => 32,
            HashAlgorithm::TupleHash128 => 16,
            HashAlgorithm::TupleHash256 => 32,
            HashAlgorithm::ParallelHash128 => 16,
            HashAlgorithm::ParallelHash256 => 32,
            HashAlgorithm::Sha224 => 28,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sha512_224 => 28,
            HashAlgorithm::Sha512_256 => 32,
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
        "kt128",
        "kt256",
        "kangarootwelve",
        "keccak224",
        "keccak256",
        "keccak384",
        "keccak512",
        "turboshake128",
        "turboshake256",
        "kmac128",
        "kmac256",
        "tuplehash128",
        "tuplehash256",
        "parallelhash128",
        "parallelhash256",
        "sha-224",
        "sha-256",
        "sha-384",
        "sha-512",
        "sha-512/224",
        "sha-512/256",
    ]
}

/// Map lib-q-core Algorithm to HashAlgorithm
pub fn algorithm_to_hash_algorithm(algorithm: Algorithm) -> Result<HashAlgorithm> {
    match algorithm {
        Algorithm::Sha3_224 => Ok(HashAlgorithm::Sha3_224),
        Algorithm::Sha3_256 => Ok(HashAlgorithm::Sha3_256),
        Algorithm::Sha3_384 => Ok(HashAlgorithm::Sha3_384),
        Algorithm::Sha3_512 => Ok(HashAlgorithm::Sha3_512),
        Algorithm::Shake128 => Ok(HashAlgorithm::Shake128),
        Algorithm::Shake256 => Ok(HashAlgorithm::Shake256),
        Algorithm::CShake128 => Ok(HashAlgorithm::Cshake128),
        Algorithm::CShake256 => Ok(HashAlgorithm::Cshake256),
        Algorithm::Kt128 => Ok(HashAlgorithm::Kt128),
        Algorithm::Kt256 => Ok(HashAlgorithm::Kt256),
        Algorithm::Keccak224 => Ok(HashAlgorithm::Keccak224),
        Algorithm::Keccak256 => Ok(HashAlgorithm::Keccak256),
        Algorithm::Keccak384 => Ok(HashAlgorithm::Keccak384),
        Algorithm::Keccak512 => Ok(HashAlgorithm::Keccak512),
        Algorithm::TurboShake128 => Ok(HashAlgorithm::TurboShake128),
        Algorithm::TurboShake256 => Ok(HashAlgorithm::TurboShake256),
        Algorithm::Kmac128 => Ok(HashAlgorithm::Kmac128),
        Algorithm::Kmac256 => Ok(HashAlgorithm::Kmac256),
        Algorithm::TupleHash128 => Ok(HashAlgorithm::TupleHash128),
        Algorithm::TupleHash256 => Ok(HashAlgorithm::TupleHash256),
        Algorithm::ParallelHash128 => Ok(HashAlgorithm::ParallelHash128),
        Algorithm::ParallelHash256 => Ok(HashAlgorithm::ParallelHash256),
        Algorithm::Sha224 => Ok(HashAlgorithm::Sha224),
        Algorithm::Sha256 => Ok(HashAlgorithm::Sha256),
        Algorithm::Sha384 => Ok(HashAlgorithm::Sha384),
        Algorithm::Sha512 => Ok(HashAlgorithm::Sha512),
        Algorithm::Sha512_224 => Ok(HashAlgorithm::Sha512_224),
        Algorithm::Sha512_256 => Ok(HashAlgorithm::Sha512_256),
        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Algorithm is not a hash algorithm",
        }),
    }
}

/// Create a hash instance by HashAlgorithm enum
pub fn create_hash(algorithm: HashAlgorithm) -> Result<Box<dyn lib_q_core::Hash>> {
    match algorithm {
        HashAlgorithm::Sha3_224 => Ok(Box::new(Sha3_224Hash::new())),
        HashAlgorithm::Sha3_256 => Ok(Box::new(Sha3_256Hash::new())),
        HashAlgorithm::Sha3_384 => Ok(Box::new(Sha3_384Hash::new())),
        HashAlgorithm::Sha3_512 => Ok(Box::new(Sha3_512Hash::new())),
        HashAlgorithm::Shake128 => Ok(Box::new(Shake128Hash::new())),
        HashAlgorithm::Shake256 => Ok(Box::new(Shake256Hash::new())),
        HashAlgorithm::Cshake128 => Ok(Box::new(CShake128Hash::new())),
        HashAlgorithm::Cshake256 => Ok(Box::new(CShake256Hash::new())),
        HashAlgorithm::Kmac128 => Ok(Box::new(Kmac128Hash::new())),
        HashAlgorithm::Kmac256 => Ok(Box::new(Kmac256Hash::new())),
        HashAlgorithm::TupleHash128 => Ok(Box::new(TupleHash128Hash::new())),
        HashAlgorithm::TupleHash256 => Ok(Box::new(TupleHash256Hash::new())),
        HashAlgorithm::ParallelHash128 => Ok(Box::new(ParallelHash128Hash::new())),
        HashAlgorithm::ParallelHash256 => Ok(Box::new(ParallelHash256Hash::new())),
        HashAlgorithm::Kt128 => Ok(Box::new(Kt128Hash::new())),
        HashAlgorithm::Kt256 => Ok(Box::new(Kt256Hash::new())),
        HashAlgorithm::Keccak224 => Ok(Box::new(Keccak224Hash::new())),
        HashAlgorithm::Keccak256 => Ok(Box::new(Keccak256Hash::new())),
        HashAlgorithm::Keccak384 => Ok(Box::new(Keccak384Hash::new())),
        HashAlgorithm::Keccak512 => Ok(Box::new(Keccak512Hash::new())),
        HashAlgorithm::TurboShake128 => Ok(Box::new(TurboShake128Hash::new())),
        HashAlgorithm::TurboShake256 => Ok(Box::new(TurboShake256Hash::new())),
        HashAlgorithm::Sha224 => Ok(Box::new(Sha224Hash::new())),
        HashAlgorithm::Sha256 => Ok(Box::new(Sha256Hash::new())),
        HashAlgorithm::Sha384 => Ok(Box::new(Sha384Hash::new())),
        HashAlgorithm::Sha512 => Ok(Box::new(Sha512Hash::new())),
        HashAlgorithm::Sha512_224 => Ok(Box::new(Sha512_224Hash::new())),
        HashAlgorithm::Sha512_256 => Ok(Box::new(Sha512_256Hash::new())),
    }
}

/// Create a hash context for the specified algorithm
pub fn create_hash_context(algorithm: Algorithm) -> Result<HashContext> {
    // Validate that this is a hash algorithm
    if algorithm.category() != lib_q_core::AlgorithmCategory::Hash {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Algorithm is not a hash algorithm",
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
        assert!(algorithms.contains(&"kt128"));
        assert!(algorithms.contains(&"kt256"));
        assert!(algorithms.contains(&"kangarootwelve"));
        assert!(algorithms.contains(&"keccak224"));
        assert!(algorithms.contains(&"keccak256"));
        assert!(algorithms.contains(&"keccak384"));
        assert!(algorithms.contains(&"keccak512"));
        assert!(algorithms.contains(&"sha-256"));
    }

    #[test]
    fn test_sha256_known_answer() {
        let h = Sha256Hash::new();
        let out = h.hash(b"").expect("sha256");
        assert_eq!(out.len(), 32);
        assert_eq!(
            out.as_slice(),
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
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
        // Test that we can't create a hash with an invalid algorithm
        // This test is now covered by the algorithm_to_hash_algorithm function
        let result = algorithm_to_hash_algorithm(Algorithm::MlDsa65); // Not a hash algorithm
        assert!(result.is_err());
    }

    #[test]
    fn hash_algorithm_output_size_exhaustive() {
        use HashAlgorithm::*;
        let all = [
            Sha3_224,
            Sha3_256,
            Sha3_384,
            Sha3_512,
            Shake128,
            Shake256,
            Cshake128,
            Cshake256,
            Kt128,
            Kt256,
            Keccak224,
            Keccak256,
            Keccak384,
            Keccak512,
            TurboShake128,
            TurboShake256,
            Kmac128,
            Kmac256,
            TupleHash128,
            TupleHash256,
            ParallelHash128,
            ParallelHash256,
            Sha224,
            Sha256,
            Sha384,
            Sha512,
            Sha512_224,
            Sha512_256,
        ];
        for a in all {
            assert!(a.output_size() > 0);
        }
    }

    #[test]
    fn create_hash_smoke_all_variants() {
        use HashAlgorithm::*;
        let variants = [
            Sha3_224,
            Sha3_256,
            Sha3_384,
            Sha3_512,
            Shake128,
            Shake256,
            Cshake128,
            Cshake256,
            Kmac128,
            Kmac256,
            TupleHash128,
            TupleHash256,
            ParallelHash128,
            ParallelHash256,
            Kt128,
            Kt256,
            Keccak224,
            Keccak256,
            Keccak384,
            Keccak512,
            TurboShake128,
            TurboShake256,
            Sha224,
            Sha256,
            Sha384,
            Sha512,
            Sha512_224,
            Sha512_256,
        ];
        for alg in variants {
            let h = create_hash(alg.clone()).expect("create_hash");
            let out = h.hash(b"coverage").expect("hash");
            assert_eq!(out.len(), alg.output_size());
        }
    }

    #[test]
    fn algorithm_to_hash_algorithm_roundtrip_core() {
        let pairs = [
            (Algorithm::Sha3_224, HashAlgorithm::Sha3_224),
            (Algorithm::Sha3_256, HashAlgorithm::Sha3_256),
            (Algorithm::Shake128, HashAlgorithm::Shake128),
            (Algorithm::CShake256, HashAlgorithm::Cshake256),
            (Algorithm::Kmac128, HashAlgorithm::Kmac128),
            (Algorithm::TupleHash256, HashAlgorithm::TupleHash256),
            (Algorithm::ParallelHash128, HashAlgorithm::ParallelHash128),
            (Algorithm::Kt128, HashAlgorithm::Kt128),
            (Algorithm::Kt256, HashAlgorithm::Kt256),
            (Algorithm::Keccak256, HashAlgorithm::Keccak256),
            (Algorithm::TurboShake128, HashAlgorithm::TurboShake128),
            (Algorithm::Sha256, HashAlgorithm::Sha256),
            (Algorithm::Sha512_256, HashAlgorithm::Sha512_256),
        ];
        for (core, expected) in pairs {
            assert_eq!(algorithm_to_hash_algorithm(core).unwrap(), expected);
        }
    }

    #[test]
    fn create_hash_context_accepts_hash_algorithms() {
        let ctx = create_hash_context(Algorithm::Sha3_256).expect("context");
        drop(ctx);
        let err = create_hash_context(Algorithm::MlKem768);
        assert!(err.is_err());
    }
}
