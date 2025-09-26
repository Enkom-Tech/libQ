//! Tests for no_std support in lib-q-sig
//!
//! These tests verify that the signature implementations work correctly
//! in no_std environments with external randomness.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "ml-dsa")]
use lib_q_core::Signature;
#[cfg(feature = "slh-dsa")]
use lib_q_core::api::Algorithm;
#[cfg(feature = "ml-dsa")]
use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
#[cfg(feature = "ml-dsa")]
use lib_q_sig::ml_dsa::MlDsa;
#[cfg(feature = "slh-dsa")]
use lib_q_sig::slh_dsa::SlhDsa;

#[cfg(feature = "slh-dsa")]
mod slh_dsa_no_std_tests {
    use super::*;

    /// Test SLH-DSA key generation with external randomness (no_std compatible)
    #[test]
    fn test_slh_dsa_key_generation_no_std() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Generate deterministic randomness
        // Shake128f requires 48 bytes (16 * 3) for key generation
        let mut randomness = [0u8; 48];
        for i in 0..48 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair = slh_dsa
            .generate_keypair_with_randomness(algorithm, &randomness)
            .expect("Key generation should succeed");

        // Verify key sizes are reasonable
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());

        // Test that same randomness produces same keys
        let keypair2 = slh_dsa
            .generate_keypair_with_randomness(algorithm, &randomness)
            .expect("Key generation should succeed");

        assert_eq!(
            keypair.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
        assert_eq!(
            keypair.secret_key().as_bytes(),
            keypair2.secret_key().as_bytes()
        );
    }

    /// Test SLH-DSA signing with external randomness (no_std compatible)
    #[test]
    fn test_slh_dsa_signing_no_std() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Generate keypair with external randomness
        // Shake128f requires 48 bytes (16 * 3) for key generation
        let mut key_randomness = [0u8; 48];
        for i in 0..48 {
            key_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair = slh_dsa
            .generate_keypair_with_randomness(algorithm, &key_randomness)
            .expect("Key generation should succeed");

        // Sign with external randomness
        let message = b"Hello, no_std SLH-DSA!";
        let mut signing_randomness = [0u8; 16]; // SLH-DSA uses first 16 bytes
        for i in 0..16 {
            signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let signature = slh_dsa
            .sign_with_randomness(
                algorithm,
                keypair.secret_key(),
                message,
                &signing_randomness,
            )
            .expect("Signing should succeed");

        // Verify signature
        let is_valid = slh_dsa
            .verify_for_algorithm(algorithm, keypair.public_key(), message, &signature)
            .expect("Verification should succeed");

        assert!(is_valid, "Signature should be valid");

        // Test deterministic signing
        let signature2 = slh_dsa
            .sign_with_randomness(
                algorithm,
                keypair.secret_key(),
                message,
                &signing_randomness,
            )
            .expect("Signing should succeed");

        assert_eq!(
            signature, signature2,
            "Signatures should be identical with same randomness"
        );
    }

    /// Test SLH-DSA error handling in no_std mode
    #[test]
    fn test_slh_dsa_no_std_error_handling() {
        let slh_dsa = SlhDsa::new();
        let algorithm = Algorithm::SlhDsaShake256128fRobust;

        // Test with insufficient randomness
        let insufficient_randomness = [0u8; 8]; // Too small
        let _result = slh_dsa.generate_keypair_with_randomness(algorithm, &insufficient_randomness);
        // This should still work as we pad/truncate as needed

        // Test with invalid algorithm
        let result = slh_dsa.generate_keypair_with_randomness(Algorithm::MlDsa65, &[0u8; 48]);
        assert!(result.is_err());
    }

    /// Test all SLH-DSA parameter sets in no_std mode
    #[test]
    fn test_all_slh_dsa_parameter_sets_no_std() {
        let slh_dsa = SlhDsa::new();
        let algorithms = [
            Algorithm::SlhDsaSha256128fRobust,
            Algorithm::SlhDsaSha256192fRobust,
            Algorithm::SlhDsaSha256256fRobust,
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in algorithms {
            // Generate deterministic randomness
            // Use 96 bytes for all parameter sets (works for 256-bit, sufficient for others)
            let mut randomness = [0u8; 96];
            for i in 0..96 {
                randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }

            let keypair = slh_dsa
                .generate_keypair_with_randomness(algorithm, &randomness)
                .expect("Key generation should succeed");

            let message = b"Test message for no_std";
            // Use appropriate randomness size for each parameter set
            let signing_randomness_size = match algorithm {
                Algorithm::SlhDsaSha256128fRobust | Algorithm::SlhDsaShake256128fRobust => 16,
                Algorithm::SlhDsaSha256192fRobust | Algorithm::SlhDsaShake256192fRobust => 24,
                Algorithm::SlhDsaSha256256fRobust | Algorithm::SlhDsaShake256256fRobust => 32,
                _ => 16,
            };
            let mut signing_randomness = [0u8; 32]; // Use fixed size array
            for i in 0..signing_randomness_size {
                signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }

            let signature = slh_dsa
                .sign_with_randomness(
                    algorithm,
                    keypair.secret_key(),
                    message,
                    &signing_randomness[..signing_randomness_size],
                )
                .expect("Signing should succeed");

            let is_valid = slh_dsa
                .verify_for_algorithm(algorithm, keypair.public_key(), message, &signature)
                .expect("Verification should succeed");

            assert!(
                is_valid,
                "Signature should be valid for algorithm: {:?}",
                algorithm
            );
        }
    }
}

#[cfg(feature = "ml-dsa")]
mod ml_dsa_no_std_tests {
    use super::*;

    /// Test ML-DSA key generation with external randomness (no_std compatible)
    #[test]
    fn test_ml_dsa_key_generation_no_std() {
        let ml_dsa = MlDsa::ml_dsa_65();

        // Generate deterministic randomness
        let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        for (i, item) in randomness.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair = ml_dsa
            .generate_keypair_with_randomness(randomness)
            .expect("Key generation should succeed");

        // Verify key sizes are reasonable
        assert!(!keypair.public_key().as_bytes().is_empty());
        assert!(!keypair.secret_key().as_bytes().is_empty());

        // Test that same randomness produces same keys
        let mut randomness2 = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        for (i, item) in randomness2.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair2 = ml_dsa
            .generate_keypair_with_randomness(randomness2)
            .expect("Key generation should succeed");

        assert_eq!(
            keypair.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
        assert_eq!(
            keypair.secret_key().as_bytes(),
            keypair2.secret_key().as_bytes()
        );
    }

    /// Test ML-DSA signing with external randomness (no_std compatible)
    #[test]
    fn test_ml_dsa_signing_no_std() {
        let ml_dsa = MlDsa::ml_dsa_65();

        // Generate keypair with external randomness
        let mut key_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        for (i, item) in key_randomness.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair = ml_dsa
            .generate_keypair_with_randomness(key_randomness)
            .expect("Key generation should succeed");

        // Sign with external randomness
        let message = b"Hello, no_std ML-DSA!";
        let mut signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        for (i, item) in signing_randomness.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let signature = ml_dsa
            .sign_with_randomness(keypair.secret_key(), message, signing_randomness)
            .expect("Signing should succeed");

        // Verify signature
        let is_valid = ml_dsa
            .verify(keypair.public_key(), message, &signature)
            .expect("Verification should succeed");

        assert!(is_valid, "Signature should be valid");

        // Test deterministic signing
        let mut signing_randomness2 = [0u8; SIGNING_RANDOMNESS_SIZE];
        for (i, item) in signing_randomness2.iter_mut().enumerate() {
            *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let signature2 = ml_dsa
            .sign_with_randomness(keypair.secret_key(), message, signing_randomness2)
            .expect("Signing should succeed");

        assert_eq!(
            signature, signature2,
            "Signatures should be identical with same randomness"
        );
    }

    /// Test all ML-DSA variants in no_std mode
    #[test]
    fn test_all_ml_dsa_variants_no_std() {
        let variants = [MlDsa::ml_dsa_44(), MlDsa::ml_dsa_65(), MlDsa::ml_dsa_87()];

        for ml_dsa in variants {
            // Generate deterministic randomness
            let mut key_randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
            for (i, item) in key_randomness.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }

            let keypair = ml_dsa
                .generate_keypair_with_randomness(key_randomness)
                .expect("Key generation should succeed");

            let message = b"Test message for no_std ML-DSA";
            let mut signing_randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
            for (i, item) in signing_randomness.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }

            let signature = ml_dsa
                .sign_with_randomness(keypair.secret_key(), message, signing_randomness)
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify(keypair.public_key(), message, &signature)
                .expect("Verification should succeed");

            assert!(is_valid, "Signature should be valid");
        }
    }
}
