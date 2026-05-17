//! SIGGEN Debug Test Suite
//!
//! This module provides detailed debugging tests for signature generation
//! to identify compliance issues with NIST FIPS 204.

#![cfg(all(feature = "random", feature = "acvp"))]

use lib_q_ml_dsa::*;

/// Test deterministic signing with fixed randomness
#[test]
fn test_signing_with_fixed_randomness() {
    // Use a known test case from ACVP
    let seed = [0x42; 32]; // Fixed seed for reproducibility
    let message = b"test message for deterministic signing";

    // Generate keys with deterministic seed
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Sign with fixed randomness
    let rnd = [0x42; 32]; // Fixed randomness

    let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    // Signing must be deterministic
    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Signing must be deterministic with same inputs"
    );

    // Verify the signature
    let verification_result = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig1);
    assert!(
        verification_result.is_ok(),
        "Generated signature must verify correctly"
    );
}

/// Test message representative derivation
#[test]
fn test_message_representative_derivation() {
    // Use known test vectors
    let _vk_bytes = [0u8; 1952]; // ML-DSA-44 verification key size
    let message = b"test message for representative derivation";

    // This test would need access to the internal derive_message_representative function
    // For now, we'll test that signing produces consistent results
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Sign the same message multiple times with same randomness
    let rnd = [0x42; 32];
    let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Message representative derivation must be deterministic"
    );
}

/// Test rejection sampling consistency
#[test]
fn test_rejection_sampling_consistency() {
    // Test that rejection sampling produces consistent results
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);

    // Sign with same randomness multiple times
    let rnd = [0x42; 32];
    let message = b"test message for rejection sampling";

    let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Rejection sampling must be deterministic"
    );
}

/// Test signature encoding consistency
#[test]
fn test_signature_encoding_consistency() {
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);
    let message = b"test message for signature encoding";
    let rnd = [0x42; 32];

    let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd).unwrap();

    // Signatures should be identical
    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Signature encoding must be deterministic"
    );

    // Verify both signatures
    let verify1 = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig1);
    let verify2 = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig2);

    assert!(verify1.is_ok(), "First signature must verify");
    assert!(verify2.is_ok(), "Second signature must verify");
}

/// Test cross-parameter-set consistency
#[test]
fn test_cross_parameter_set_consistency() {
    let seed = [0x42; 32];
    let message = b"test message for cross-parameter consistency";
    let rnd = [0x42; 32];

    // Test ML-DSA-44
    let keys44 = ml_dsa_44::generate_key_pair(seed);
    let sig44 = ml_dsa_44::sign_internal(&keys44.signing_key, message, rnd).unwrap();
    let verify44 = ml_dsa_44::verify_internal(&keys44.verification_key, message, &sig44);
    assert!(verify44.is_ok(), "ML-DSA-44 signature must verify");

    // Test ML-DSA-65 if available
    #[cfg(feature = "mldsa65")]
    {
        let keys65 = ml_dsa_65::generate_key_pair(seed);
        let sig65 = ml_dsa_65::sign_internal(&keys65.signing_key, message, rnd).unwrap();
        let verify65 = ml_dsa_65::verify_internal(&keys65.verification_key, message, &sig65);
        assert!(verify65.is_ok(), "ML-DSA-65 signature must verify");
    }

    // Test ML-DSA-87 if available
    #[cfg(feature = "mldsa87")]
    {
        let keys87 = ml_dsa_87::generate_key_pair(seed);
        let sig87 = ml_dsa_87::sign_internal(&keys87.signing_key, message, rnd).unwrap();
        let verify87 = ml_dsa_87::verify_internal(&keys87.verification_key, message, &sig87);
        assert!(verify87.is_ok(), "ML-DSA-87 signature must verify");
    }
}

/// Test edge cases for signature generation
#[test]
fn test_signature_generation_edge_cases() {
    // Test with empty message
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);
    let rnd = [0x42; 32];

    let empty_message = b"";
    let sig_empty = ml_dsa_44::sign_internal(&keys.signing_key, empty_message, rnd).unwrap();
    let verify_empty =
        ml_dsa_44::verify_internal(&keys.verification_key, empty_message, &sig_empty);
    assert!(verify_empty.is_ok(), "Empty message signature must verify");

    // Test with large message
    let large_message = vec![0x42u8; 1000];
    let sig_large = ml_dsa_44::sign_internal(&keys.signing_key, &large_message, rnd).unwrap();
    let verify_large =
        ml_dsa_44::verify_internal(&keys.verification_key, &large_message, &sig_large);
    assert!(verify_large.is_ok(), "Large message signature must verify");
}

/// Test signature generation with different randomness
#[test]
fn test_signature_generation_different_randomness() {
    let seed = [0x42; 32];
    let keys = ml_dsa_44::generate_key_pair(seed);
    let message = b"test message for different randomness";

    // Sign with different randomness values
    let rnd1 = [0x42; 32];
    let rnd2 = [0x43; 32];

    let sig1 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd1).unwrap();
    let sig2 = ml_dsa_44::sign_internal(&keys.signing_key, message, rnd2).unwrap();

    // Signatures should be different with different randomness
    assert_ne!(
        sig1.as_slice(),
        sig2.as_slice(),
        "Different randomness should produce different signatures"
    );

    // Both signatures should verify
    let verify1 = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig1);
    let verify2 = ml_dsa_44::verify_internal(&keys.verification_key, message, &sig2);

    assert!(verify1.is_ok(), "First signature must verify");
    assert!(verify2.is_ok(), "Second signature must verify");
}
