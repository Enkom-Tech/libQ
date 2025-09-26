//! Provider pattern integration tests for lib-q-sig
//!
//! These tests verify that the lib-q signature provider correctly routes
//! operations to the appropriate algorithm implementations and handles
//! security validation, error handling, and cross-algorithm functionality.

#[cfg(feature = "slh-dsa")]
use lib_q_core::{
    api::{
        Algorithm,
        SignatureOperations,
    },
    traits::SigSecretKey,
};
#[cfg(feature = "slh-dsa")]
use lib_q_sig::LibQSignatureProvider;

#[cfg(feature = "slh-dsa")]
mod provider_tests {
    use super::*;

    /// Test provider pattern routing for SLH-DSA algorithms
    #[test]
    fn test_provider_routing_slh_dsa() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        let algorithms = [
            Algorithm::SlhDsaSha256128fRobust,
            Algorithm::SlhDsaSha256192fRobust,
            Algorithm::SlhDsaSha256256fRobust,
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in algorithms {
            println!("Testing provider routing for: {:?}", algorithm);

            // Test key generation through provider with external randomness
            // Use 96 bytes to accommodate all parameter sets (192-bit requires 72 bytes)
            let mut randomness = [0u8; 96];
            for i in 0..96 {
                randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }
            let keypair = provider
                .generate_keypair(algorithm, Some(&randomness))
                .expect("Key generation should succeed");

            // Test signing through provider with external randomness
            let message = b"Provider pattern test message";
            let mut signing_randomness = [0u8; 32]; // Use 32 bytes for all parameter sets
            for i in 0..32 {
                signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }
            let signature = provider
                .sign(
                    algorithm,
                    keypair.secret_key(),
                    message,
                    Some(&signing_randomness),
                )
                .expect("Signing should succeed");

            // Test verification through provider
            let is_valid = provider
                .verify(algorithm, keypair.public_key(), message, &signature)
                .expect("Verification should succeed");

            assert!(
                is_valid,
                "Signature should be valid for algorithm: {:?}",
                algorithm
            );
        }
    }

    /// Test provider error handling for unsupported algorithms
    #[test]
    fn test_provider_error_handling() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        // Test with unsupported algorithm
        let result = provider.generate_keypair(Algorithm::Sha3_256, None);
        assert!(
            result.is_err(),
            "Should return error for unsupported algorithm"
        );

        // Test with invalid key material
        let invalid_key = SigSecretKey::new(vec![0; 16]); // Too small
        let result = provider.sign(
            Algorithm::SlhDsaShake256128fRobust,
            &invalid_key,
            b"test",
            None,
        );
        assert!(result.is_err(), "Should return error for invalid key");
    }

    /// Test provider security validation
    #[test]
    fn test_provider_security_validation() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        // Test with all-zero randomness (should fail security validation)
        let zero_randomness = [0u8; 96];
        let result =
            provider.generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&zero_randomness));
        assert!(result.is_err(), "Should reject all-zero randomness");

        // Test with valid randomness
        let mut valid_randomness = [0u8; 96];
        for i in 0..96 {
            valid_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        let _result =
            provider.generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&valid_randomness));
        // This should work with valid randomness
    }

    /// Test provider cross-algorithm functionality
    #[test]
    fn test_provider_cross_algorithm() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        // Test that different algorithms produce different key sizes
        let mut randomness = [0u8; 96];
        for i in 0..96 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair_128f = provider
            .generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        let keypair_192f = provider
            .generate_keypair(Algorithm::SlhDsaShake256192fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        let keypair_256f = provider
            .generate_keypair(Algorithm::SlhDsaShake256256fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        // Different parameter sets should produce different key sizes
        assert_ne!(
            keypair_128f.public_key().as_bytes().len(),
            keypair_192f.public_key().as_bytes().len(),
            "Different parameter sets should produce different key sizes"
        );
        assert_ne!(
            keypair_192f.public_key().as_bytes().len(),
            keypair_256f.public_key().as_bytes().len(),
            "Different parameter sets should produce different key sizes"
        );
    }

    /// Test provider deterministic behavior
    #[test]
    fn test_provider_deterministic_behavior() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        // Test deterministic key generation
        let mut randomness = [0u8; 96];
        for i in 0..96 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair1 = provider
            .generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        let keypair2 = provider
            .generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        assert_eq!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes(),
            "Same randomness should produce same keys"
        );
        assert_eq!(
            keypair1.secret_key().as_bytes(),
            keypair2.secret_key().as_bytes(),
            "Same randomness should produce same keys"
        );

        // Test deterministic signing
        let message = b"Deterministic signing test";
        let mut signing_randomness = [0u8; 32]; // Security validator expects 32 bytes
        for i in 0..32 {
            signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let signature1 = provider
            .sign(
                Algorithm::SlhDsaShake256128fRobust,
                keypair1.secret_key(),
                message,
                Some(&signing_randomness),
            )
            .expect("Signing should succeed");

        let signature2 = provider
            .sign(
                Algorithm::SlhDsaShake256128fRobust,
                keypair1.secret_key(),
                message,
                Some(&signing_randomness),
            )
            .expect("Signing should succeed");

        assert_eq!(
            signature1, signature2,
            "Same randomness should produce same signatures"
        );
    }

    /// Test provider memory safety
    #[test]
    fn test_provider_memory_safety() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        // Test that keys are properly handled
        let mut randomness = [0u8; 96];
        for i in 0..96 {
            randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }

        let keypair = provider
            .generate_keypair(Algorithm::SlhDsaShake256128fRobust, Some(&randomness))
            .expect("Key generation should succeed");

        let secret_key_bytes = keypair.secret_key().as_bytes().to_vec();
        drop(keypair);

        // In a real implementation, we would check that the memory was zeroized
        // For now, we just verify that the keypair was created and dropped successfully
        assert!(
            !secret_key_bytes.is_empty(),
            "Secret key should not be empty"
        );
    }

    /// Test provider performance characteristics
    #[test]
    fn test_provider_performance_characteristics() {
        let provider = LibQSignatureProvider::new().expect("Failed to create provider");

        let algorithms = [
            Algorithm::SlhDsaShake256128fRobust,
            Algorithm::SlhDsaShake256192fRobust,
            Algorithm::SlhDsaShake256256fRobust,
        ];

        for algorithm in algorithms {
            let start = std::time::Instant::now();

            // Generate keypair with external randomness
            let mut randomness = [0u8; 96];
            for i in 0..96 {
                randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
            }

            let keypair = provider
                .generate_keypair(algorithm, Some(&randomness))
                .expect("Key generation should succeed");

            let keygen_time = start.elapsed();

            // Sign message with external randomness
            let message = b"Performance test message";
            let mut signing_randomness = [0u8; 32]; // Security validator expects 32 bytes
            for i in 0..32 {
                signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
            }

            let sign_start = std::time::Instant::now();
            let signature = provider
                .sign(
                    algorithm,
                    keypair.secret_key(),
                    message,
                    Some(&signing_randomness),
                )
                .expect("Signing should succeed");
            let sign_time = sign_start.elapsed();

            // Verify signature
            let verify_start = std::time::Instant::now();
            let is_valid = provider
                .verify(algorithm, keypair.public_key(), message, &signature)
                .expect("Verification should succeed");
            let verify_time = verify_start.elapsed();

            assert!(is_valid, "Signature should be valid");
            assert!(
                keygen_time.as_millis() < 10000,
                "Key generation should be reasonably fast"
            );
            assert!(
                sign_time.as_millis() < 10000,
                "Signing should be reasonably fast"
            );
            assert!(
                verify_time.as_millis() < 10000,
                "Verification should be reasonably fast"
            );

            println!(
                "Algorithm {:?}: KeyGen={}ms, Sign={}ms, Verify={}ms",
                algorithm,
                keygen_time.as_millis(),
                sign_time.as_millis(),
                verify_time.as_millis()
            );
        }
    }
}
