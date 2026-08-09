//! Determinism and Interoperability Tests for ML-DSA
//!
//! This module provides comprehensive tests to ensure that ML-DSA operations
//! are deterministic and produce identical outputs across different implementations
//! (portable vs SIMD) for the same inputs.

#![cfg(all(feature = "random", feature = "acvp"))]

use lib_q_ml_dsa::rng::MLDsaRng;
use lib_q_ml_dsa::*;

fn label_seed(s: &[u8]) -> [u8; 32] {
    assert!(
        s.len() <= 32,
        "determinism tests use at most 32-byte labels"
    );
    let mut out = [0u8; 32];
    out[..s.len()].copy_from_slice(s);
    out
}

/// Test that key generation is deterministic across implementations
#[test]
fn test_keygen_determinism_portable_vs_simd() {
    let seed = b"determinism_test_seed_12345";

    // Generate keys with portable implementation
    let mut rng_portable = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness_portable = [0u8; 32];
    rng_portable
        .fill_bytes(&mut randomness_portable)
        .expect("RNG should not fail");

    let keys_portable = ml_dsa_44::portable::generate_key_pair(randomness_portable);
    assert!(
        !keys_portable.signing_key.as_slice().is_empty(),
        "Portable keygen should produce non-empty keys"
    );

    // Generate keys with SIMD implementation (if available)
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    {
        let mut rng_simd = MLDsaRng::new_deterministic(label_seed(seed));
        let mut randomness_simd = [0u8; 32];
        rng_simd
            .fill_bytes(&mut randomness_simd)
            .expect("RNG should not fail");

        let keys_simd = ml_dsa_44::avx2::generate_key_pair(randomness_simd);

        // Keys should be identical
        assert_eq!(
            keys_portable.signing_key.as_slice(),
            keys_simd.signing_key.as_slice(),
            "Signing keys should be identical between portable and SIMD implementations"
        );

        assert_eq!(
            keys_portable.verification_key.as_slice(),
            keys_simd.verification_key.as_slice(),
            "Verification keys should be identical between portable and SIMD implementations"
        );
    }
}

/// Test that signing is deterministic across implementations
#[test]
fn test_signing_determinism_portable_vs_simd() {
    let seed = b"signing_determinism_test_seed";
    let message = b"test message for deterministic signing";

    // Generate keys with portable implementation
    let mut rng_portable = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness_portable = [0u8; 32];
    rng_portable
        .fill_bytes(&mut randomness_portable)
        .expect("RNG should not fail");

    let keys_portable = ml_dsa_44::portable::generate_key_pair(randomness_portable);

    // Sign with portable implementation
    let mut rng_sign_portable = MLDsaRng::new_deterministic(label_seed(b"signing_randomness_seed"));
    let mut signing_randomness_portable = [0u8; 32];
    rng_sign_portable
        .fill_bytes(&mut signing_randomness_portable)
        .expect("RNG should not fail");

    let signature_portable = ml_dsa_44::portable::sign_internal(
        &keys_portable.signing_key,
        message,
        signing_randomness_portable,
    )
    .expect("Signing should succeed");
    assert!(
        !signature_portable.as_slice().is_empty(),
        "Portable signing should produce non-empty signature"
    );

    // Sign with SIMD implementation (if available)
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    {
        let mut rng_simd = MLDsaRng::new_deterministic(label_seed(seed));
        let mut randomness_simd = [0u8; 32];
        rng_simd
            .fill_bytes(&mut randomness_simd)
            .expect("RNG should not fail");

        let keys_simd = ml_dsa_44::avx2::generate_key_pair(randomness_simd);

        let mut rng_sign_simd = MLDsaRng::new_deterministic(label_seed(b"signing_randomness_seed"));
        let mut signing_randomness_simd = [0u8; 32];
        rng_sign_simd
            .fill_bytes(&mut signing_randomness_simd)
            .expect("RNG should not fail");

        let signature_simd = ml_dsa_44::avx2::sign_internal(
            &keys_simd.signing_key,
            message,
            signing_randomness_simd,
        )
        .expect("Signing should succeed");

        // Signatures should be identical
        assert_eq!(
            signature_portable.as_slice(),
            signature_simd.as_slice(),
            "Signatures should be identical between portable and SIMD implementations"
        );
    }
}

/// Test that verification works across implementations
#[test]
fn test_verification_cross_implementation() {
    let seed = b"verification_cross_test_seed";
    let message = b"test message for cross-implementation verification";

    // Generate keys with portable implementation
    let mut rng_portable = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness_portable = [0u8; 32];
    rng_portable
        .fill_bytes(&mut randomness_portable)
        .expect("RNG should not fail");

    let keys_portable = ml_dsa_44::portable::generate_key_pair(randomness_portable);

    // Sign with portable implementation
    let mut rng_sign_portable = MLDsaRng::new_deterministic(label_seed(b"signing_randomness_seed"));
    let mut signing_randomness_portable = [0u8; 32];
    rng_sign_portable
        .fill_bytes(&mut signing_randomness_portable)
        .expect("RNG should not fail");

    let signature_portable = ml_dsa_44::portable::sign_internal(
        &keys_portable.signing_key,
        message,
        signing_randomness_portable,
    )
    .expect("Signing should succeed");

    // Verify with portable implementation
    let verification_result_portable = ml_dsa_44::portable::verify_internal(
        &keys_portable.verification_key,
        message,
        &signature_portable,
    );

    assert!(
        verification_result_portable.is_ok(),
        "Portable signature should verify correctly"
    );

    // Verify with SIMD implementation (if available)
    #[cfg(all(feature = "simd256", target_arch = "x86_64"))]
    {
        let verification_result_simd = ml_dsa_44::avx2::verify_internal(
            &keys_portable.verification_key,
            message,
            &signature_portable,
        );

        assert!(
            verification_result_simd.is_ok(),
            "SIMD implementation should verify portable signature correctly"
        );
    }
}

/// Test that same seed produces identical results across multiple runs
#[test]
fn test_deterministic_reproducibility() {
    let seed = b"reproducibility_test_seed";
    let message = b"test message for reproducibility";

    // Run 1
    let mut rng1 = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness1 = [0u8; 32];
    rng1.fill_bytes(&mut randomness1)
        .expect("RNG should not fail");

    let keys1 = ml_dsa_44::generate_key_pair(randomness1);

    let mut rng_sign1 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
    let mut signing_randomness1 = [0u8; 32];
    rng_sign1
        .fill_bytes(&mut signing_randomness1)
        .expect("RNG should not fail");

    let signature1 = ml_dsa_44::sign_internal(&keys1.signing_key, message, signing_randomness1)
        .expect("Signing should succeed");

    // Run 2 - should produce identical results
    let mut rng2 = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness2 = [0u8; 32];
    rng2.fill_bytes(&mut randomness2)
        .expect("RNG should not fail");

    let keys2 = ml_dsa_44::generate_key_pair(randomness2);

    let mut rng_sign2 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
    let mut signing_randomness2 = [0u8; 32];
    rng_sign2
        .fill_bytes(&mut signing_randomness2)
        .expect("RNG should not fail");

    let signature2 = ml_dsa_44::sign_internal(&keys2.signing_key, message, signing_randomness2)
        .expect("Signing should succeed");

    // Results should be identical
    assert_eq!(
        keys1.signing_key.as_slice(),
        keys2.signing_key.as_slice(),
        "Signing keys should be identical across runs"
    );

    assert_eq!(
        keys1.verification_key.as_slice(),
        keys2.verification_key.as_slice(),
        "Verification keys should be identical across runs"
    );

    assert_eq!(
        signature1.as_slice(),
        signature2.as_slice(),
        "Signatures should be identical across runs"
    );
}

/// Test that different seeds produce different results
#[test]
fn test_different_seeds_produce_different_results() {
    let seed1 = b"seed_one_12345";
    let seed2 = b"seed_two_67890";
    let message = b"test message for different seeds";

    // Generate keys with seed1
    let mut rng1 = MLDsaRng::new_deterministic(label_seed(seed1));
    let mut randomness1 = [0u8; 32];
    rng1.fill_bytes(&mut randomness1)
        .expect("RNG should not fail");

    let keys1 = ml_dsa_44::generate_key_pair(randomness1);

    // Generate keys with seed2
    let mut rng2 = MLDsaRng::new_deterministic(label_seed(seed2));
    let mut randomness2 = [0u8; 32];
    rng2.fill_bytes(&mut randomness2)
        .expect("RNG should not fail");

    let keys2 = ml_dsa_44::generate_key_pair(randomness2);

    // Keys should be different
    assert_ne!(
        keys1.signing_key.as_slice(),
        keys2.signing_key.as_slice(),
        "Different seeds should produce different signing keys"
    );

    assert_ne!(
        keys1.verification_key.as_slice(),
        keys2.verification_key.as_slice(),
        "Different seeds should produce different verification keys"
    );

    // Sign with both keys
    let mut rng_sign1 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
    let mut signing_randomness1 = [0u8; 32];
    rng_sign1
        .fill_bytes(&mut signing_randomness1)
        .expect("RNG should not fail");

    let signature1 = ml_dsa_44::sign_internal(&keys1.signing_key, message, signing_randomness1)
        .expect("Signing should succeed");

    let mut rng_sign2 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
    let mut signing_randomness2 = [0u8; 32];
    rng_sign2
        .fill_bytes(&mut signing_randomness2)
        .expect("RNG should not fail");

    let signature2 = ml_dsa_44::sign_internal(&keys2.signing_key, message, signing_randomness2)
        .expect("Signing should succeed");

    // Signatures should be different
    assert_ne!(
        signature1.as_slice(),
        signature2.as_slice(),
        "Different keys should produce different signatures"
    );
}

/// Test that all ML-DSA parameter sets work deterministically
#[test]
fn test_all_parameter_sets_deterministic() {
    let seed = b"parameter_set_test_seed";
    let message = b"test message for all parameter sets";

    // Test ML-DSA-44
    let mut rng44 = MLDsaRng::new_deterministic(label_seed(seed));
    let mut randomness44 = [0u8; 32];
    rng44
        .fill_bytes(&mut randomness44)
        .expect("RNG should not fail");

    let keys44 = ml_dsa_44::generate_key_pair(randomness44);

    let mut rng_sign44 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
    let mut signing_randomness44 = [0u8; 32];
    rng_sign44
        .fill_bytes(&mut signing_randomness44)
        .expect("RNG should not fail");

    let signature44 = ml_dsa_44::sign_internal(&keys44.signing_key, message, signing_randomness44)
        .expect("ML-DSA-44 signing should succeed");

    let verification44 =
        ml_dsa_44::verify_internal(&keys44.verification_key, message, &signature44);
    assert!(
        verification44.is_ok(),
        "ML-DSA-44 verification should succeed"
    );

    // Test ML-DSA-65
    #[cfg(feature = "mldsa65")]
    {
        let mut rng65 = MLDsaRng::new_deterministic(label_seed(seed));
        let mut randomness65 = [0u8; 32];
        rng65
            .fill_bytes(&mut randomness65)
            .expect("RNG should not fail");

        let keys65 = ml_dsa_65::generate_key_pair(randomness65);

        let mut rng_sign65 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
        let mut signing_randomness65 = [0u8; 32];
        rng_sign65
            .fill_bytes(&mut signing_randomness65)
            .expect("RNG should not fail");

        let signature65 =
            ml_dsa_65::sign_internal(&keys65.signing_key, message, signing_randomness65)
                .expect("ML-DSA-65 signing should succeed");

        let verification65 =
            ml_dsa_65::verify_internal(&keys65.verification_key, message, &signature65);
        assert!(
            verification65.is_ok(),
            "ML-DSA-65 verification should succeed"
        );
    }

    // Test ML-DSA-87
    #[cfg(feature = "mldsa87")]
    {
        let mut rng87 = MLDsaRng::new_deterministic(label_seed(seed));
        let mut randomness87 = [0u8; 32];
        rng87
            .fill_bytes(&mut randomness87)
            .expect("RNG should not fail");

        let keys87 = ml_dsa_87::generate_key_pair(randomness87);

        let mut rng_sign87 = MLDsaRng::new_deterministic(label_seed(b"signing_seed"));
        let mut signing_randomness87 = [0u8; 32];
        rng_sign87
            .fill_bytes(&mut signing_randomness87)
            .expect("RNG should not fail");

        let signature87 =
            ml_dsa_87::sign_internal(&keys87.signing_key, message, signing_randomness87)
                .expect("ML-DSA-87 signing should succeed");

        let verification87 =
            ml_dsa_87::verify_internal(&keys87.verification_key, message, &signature87);
        assert!(
            verification87.is_ok(),
            "ML-DSA-87 verification should succeed"
        );
    }
}

/// Test that RNG state is properly isolated between operations
#[test]
fn test_rng_state_isolation_in_ml_dsa() {
    let seed = b"isolation_test_seed";

    // Create two RNG instances with same seed
    let mut rng1 = MLDsaRng::new_deterministic(label_seed(seed));
    let mut rng2 = MLDsaRng::new_deterministic(label_seed(seed));

    // Generate randomness for key generation
    let mut randomness1 = [0u8; 32];
    let mut randomness2 = [0u8; 32];

    rng1.fill_bytes(&mut randomness1)
        .expect("RNG should not fail");
    rng2.fill_bytes(&mut randomness2)
        .expect("RNG should not fail");

    // Should be identical
    assert_eq!(
        randomness1, randomness2,
        "RNG instances should produce identical output"
    );

    // Generate keys
    let keys1 = ml_dsa_44::generate_key_pair(randomness1);
    let keys2 = ml_dsa_44::generate_key_pair(randomness2);

    // Keys should be identical
    assert_eq!(
        keys1.signing_key.as_slice(),
        keys2.signing_key.as_slice(),
        "Keys should be identical with identical RNG state"
    );

    // Continue with RNG instances
    let mut signing_randomness1 = [0u8; 32];
    let mut signing_randomness2 = [0u8; 32];

    rng1.fill_bytes(&mut signing_randomness1)
        .expect("RNG should not fail");
    rng2.fill_bytes(&mut signing_randomness2)
        .expect("RNG should not fail");

    // Should still be identical
    assert_eq!(
        signing_randomness1, signing_randomness2,
        "RNG instances should maintain identical state"
    );
}
