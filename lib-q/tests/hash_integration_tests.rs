//! Integration tests for lib-Q hash functionality
//!
//! These tests verify that the hash provider integration works correctly
//! through the main lib-Q system.

use lib_q_core::api::{
    Algorithm,
    AlgorithmCategory,
};
use lib_q_core::contexts::HashContext;
use lib_q_core::error::Error;
#[cfg(feature = "alloc")]
use lib_q_hash::LibQHashProvider;

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_integration() {
    // Create a hash context
    let mut ctx = HashContext::new();

    // Create and set the hash provider
    let provider = LibQHashProvider::new().expect("Failed to create hash provider");
    ctx.set_provider(Box::new(provider));

    // Test SHA3-256
    let test_data = b"Hello, lib-Q!";
    let result = ctx.hash(Algorithm::Sha3_256, test_data);
    assert!(result.is_ok(), "SHA3-256 should work through the provider");

    if let Ok(hash) = result {
        assert_eq!(hash.len(), 32, "SHA3-256 should produce 32-byte hash");
    }

    // Test SHA3-512
    let result = ctx.hash(Algorithm::Sha3_512, test_data);
    assert!(result.is_ok(), "SHA3-512 should work through the provider");

    if let Ok(hash) = result {
        assert_eq!(hash.len(), 64, "SHA3-512 should produce 64-byte hash");
    }

    // Test SHAKE128
    let result = ctx.hash(Algorithm::Shake128, test_data);
    assert!(result.is_ok(), "SHAKE128 should work through the provider");

    if let Ok(hash) = result {
        assert_eq!(hash.len(), 16, "SHAKE128 should produce 16-byte hash");
    }

    // Test SHAKE256
    let result = ctx.hash(Algorithm::Shake256, test_data);
    assert!(result.is_ok(), "SHAKE256 should work through the provider");

    if let Ok(hash) = result {
        assert_eq!(hash.len(), 32, "SHAKE256 should produce 32-byte hash");
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_unsupported_algorithm() {
    // Create a hash context
    let mut ctx = HashContext::new();

    // Create and set the hash provider
    let provider = LibQHashProvider::new().expect("Failed to create hash provider");
    ctx.set_provider(Box::new(provider));

    // Test with a non-hash algorithm (should fail)
    let test_data = b"Hello, lib-Q!";
    let result = ctx.hash(Algorithm::MlDsa65, test_data);
    assert!(result.is_err(), "Non-hash algorithm should fail");

    if let Err(Error::InvalidAlgorithm { .. }) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidAlgorithm error for non-hash algorithm");
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_algorithm_validation() {
    // Test that all hash algorithms are properly categorized
    let hash_algorithms = [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::CShake128,
        Algorithm::CShake256,
        Algorithm::Keccak224,
        Algorithm::Keccak256,
        Algorithm::Keccak384,
        Algorithm::Keccak512,
        Algorithm::Kt128,
        Algorithm::Kt256,
        Algorithm::TurboShake128,
        Algorithm::TurboShake256,
        Algorithm::Kmac128,
        Algorithm::Kmac256,
        Algorithm::TupleHash128,
        Algorithm::TupleHash256,
        Algorithm::ParallelHash128,
        Algorithm::ParallelHash256,
    ];

    for algorithm in &hash_algorithms {
        assert_eq!(
            algorithm.category(),
            AlgorithmCategory::Hash,
            "Algorithm {:?} should be categorized as Hash",
            algorithm
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_consistency() {
    // Create a hash context
    let mut ctx = HashContext::new();

    // Create and set the hash provider
    let provider = LibQHashProvider::new().expect("Failed to create hash provider");
    ctx.set_provider(Box::new(provider));

    // Test that the same input produces the same output
    let test_data = b"Consistent hashing test";

    let hash1 = ctx
        .hash(Algorithm::Sha3_256, test_data)
        .expect("First hash should work");
    let hash2 = ctx
        .hash(Algorithm::Sha3_256, test_data)
        .expect("Second hash should work");

    assert_eq!(hash1, hash2, "Same input should produce same hash output");

    // Test that different inputs produce different outputs
    let different_data = b"Different input data";
    let hash3 = ctx
        .hash(Algorithm::Sha3_256, different_data)
        .expect("Third hash should work");

    assert_ne!(
        hash1, hash3,
        "Different inputs should produce different hash outputs"
    );
}

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_empty_input() {
    // Create a hash context
    let mut ctx = HashContext::new();

    // Create and set the hash provider
    let provider = LibQHashProvider::new().expect("Failed to create hash provider");
    ctx.set_provider(Box::new(provider));

    // Test with empty input
    let empty_data = b"";
    let result = ctx.hash(Algorithm::Sha3_256, empty_data);
    assert!(result.is_ok(), "Empty input should be valid");

    if let Ok(hash) = result {
        assert_eq!(
            hash.len(),
            32,
            "Empty input should still produce 32-byte hash"
        );
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_hash_provider_large_input() {
    // Create a hash context
    let mut ctx = HashContext::new();

    // Create and set the hash provider
    let provider = LibQHashProvider::new().expect("Failed to create hash provider");
    ctx.set_provider(Box::new(provider));

    // Test with large input (1MB)
    let large_data = vec![0x42u8; 1024 * 1024];
    let result = ctx.hash(Algorithm::Sha3_256, &large_data);
    assert!(result.is_ok(), "Large input should be valid");

    if let Ok(hash) = result {
        assert_eq!(
            hash.len(),
            32,
            "Large input should still produce 32-byte hash"
        );
    }
}
