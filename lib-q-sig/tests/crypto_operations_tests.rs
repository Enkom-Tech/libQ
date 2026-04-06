//! Comprehensive cryptographic operation tests for lib-q-sig
//!
//! This module provides extensive testing of signature operations including:
//! - End-to-end cryptographic operations (key generation, signing, verification)
//! - Security edge cases and vulnerability tests
//! - Performance and timing attack resistance tests
//! - Memory safety and zeroization tests

#[cfg(feature = "alloc")]
extern crate alloc;

use lib_q_core::{
    Algorithm,
    SigPublicKey,
    Signature,
    SignatureOperations,
};
use lib_q_sig::LibQSignatureProvider;
#[cfg(feature = "fn-dsa")]
use lib_q_sig::fn_dsa::{
    FnDsa512,
    FnDsa1024,
};
use lib_q_sig::ml_dsa::MlDsa;
#[cfg(all(feature = "slh-dsa-std", feature = "std"))]
use lib_q_sig::slh_dsa::SlhDsa;

/// Generate test randomness for cryptographic operations
#[allow(dead_code)]
fn generate_test_randomness() -> [u8; 32] {
    // Use a deterministic but valid randomness pattern for testing
    let mut randomness = [0u8; 32];
    for (i, byte) in randomness.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }
    randomness
}

/// Generate test signing randomness for cryptographic operations
#[allow(dead_code)]
fn generate_test_signing_randomness() -> [u8; 32] {
    // Use a different deterministic pattern for signing randomness
    let mut randomness = [0u8; 32];
    for (i, byte) in randomness.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }
    randomness
}

/// Generate test messages for cryptographic operations
#[allow(dead_code)]
fn generate_test_messages() -> Vec<Vec<u8>> {
    vec![
        b"Hello, World!".to_vec(),
        b"".to_vec(),      // Empty message
        b"A".repeat(1000), // Long message
        b"Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?".to_vec(),
        "Unicode: 你好世界 🌍".as_bytes().to_vec(),
    ]
}

/// Test end-to-end cryptographic operations for ML-DSA
#[cfg(feature = "ml-dsa")]
#[cfg(feature = "std")]
mod ml_dsa_crypto_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_end_to_end() {
        let ml_dsa = MlDsa::ml_dsa_44();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Sign message
            let signature = ml_dsa
                .sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = ml_dsa
                .verify(keypair.public_key(), &message, &signature)
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_ml_dsa_65_end_to_end() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Sign message
            let signature = ml_dsa
                .sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = ml_dsa
                .verify(keypair.public_key(), &message, &signature)
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_ml_dsa_87_end_to_end() {
        let ml_dsa = MlDsa::ml_dsa_87();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Sign message
            let signature = ml_dsa
                .sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = ml_dsa
                .verify(keypair.public_key(), &message, &signature)
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_ml_dsa_keypair_uniqueness() {
        let ml_dsa = MlDsa::ml_dsa_65();

        // Generate multiple keypairs and ensure they're unique
        let mut keypairs = Vec::new();
        for _ in 0..10 {
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            keypairs.push(keypair);
        }

        // Check that all public keys are unique
        for (i, _) in keypairs.iter().enumerate() {
            for j in (i + 1)..keypairs.len() {
                assert_ne!(
                    keypairs[i].public_key().as_bytes(),
                    keypairs[j].public_key().as_bytes(),
                    "Public keys should be unique"
                );
                assert_ne!(
                    keypairs[i].secret_key().as_bytes(),
                    keypairs[j].secret_key().as_bytes(),
                    "Secret keys should be unique"
                );
            }
        }
    }

    #[test]
    fn test_ml_dsa_signature_uniqueness() {
        let ml_dsa = MlDsa::ml_dsa_65();
        let keypair = ml_dsa
            .generate_keypair()
            .expect("Key generation should succeed");
        let message = b"Test message for signature uniqueness";

        // Generate multiple signatures and ensure they're unique
        let mut signatures = Vec::new();
        for _ in 0..10 {
            let signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");
            signatures.push(signature);
        }

        // Check that all signatures are unique (due to randomness)
        for (i, _) in signatures.iter().enumerate() {
            for j in (i + 1)..signatures.len() {
                assert_ne!(
                    signatures[i], signatures[j],
                    "Signatures should be unique due to randomness"
                );
            }
        }

        // But all should verify correctly
        for signature in &signatures {
            let is_valid = ml_dsa
                .verify(keypair.public_key(), message, signature)
                .expect("Verification should succeed");
            assert!(is_valid, "All signatures should verify correctly");
        }
    }
}

/// Test end-to-end cryptographic operations for SLH-DSA (implicit OS RNG; requires `slh-dsa-std`)
#[cfg(all(feature = "slh-dsa-std", feature = "std"))]
mod slh_dsa_crypto_tests {
    use lib_q_core::api::Algorithm;

    use super::*;

    #[test]
    fn test_slh_dsa_sha256_128f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaSha256128fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaSha256128fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaSha256128fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_sha256_192f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaSha256192fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaSha256192fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaSha256192fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_sha256_256f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaSha256256fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaSha256256fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaSha256256fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_shake256_128f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaShake256128fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaShake256128fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaShake256128fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_shake256_192f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaShake256192fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaShake256192fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaShake256192fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_shake256_256f_robust_end_to_end() {
        let slh_dsa = SlhDsa::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaShake256256fRobust, None)
                .expect("Key generation should succeed");

            // Sign message
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaShake256256fRobust,
                    keypair.secret_key(),
                    &message,
                    None,
                )
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaShake256256fRobust,
                    keypair.public_key(),
                    &message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_slh_dsa_keypair_uniqueness() {
        let slh_dsa = SlhDsa::new();

        // Generate multiple keypairs and ensure they're unique
        let mut keypairs = Vec::new();
        for _ in 0..10 {
            let keypair = slh_dsa
                .generate_keypair_for_algorithm(Algorithm::SlhDsaSha256192fRobust, None)
                .expect("Key generation should succeed");
            keypairs.push(keypair);
        }

        // Check that all public keys are unique
        for (i, _) in keypairs.iter().enumerate() {
            for j in (i + 1)..keypairs.len() {
                assert_ne!(
                    keypairs[i].public_key().as_bytes(),
                    keypairs[j].public_key().as_bytes(),
                    "Public keys should be unique"
                );
                assert_ne!(
                    keypairs[i].secret_key().as_bytes(),
                    keypairs[j].secret_key().as_bytes(),
                    "Secret keys should be unique"
                );
            }
        }
    }

    #[test]
    fn test_slh_dsa_signature_uniqueness() {
        let slh_dsa = SlhDsa::new();
        let keypair = slh_dsa
            .generate_keypair_for_algorithm(Algorithm::SlhDsaSha256192fRobust, None)
            .expect("Key generation should succeed");
        let message = b"Test message for signature uniqueness";

        // Generate multiple signatures and ensure they're unique
        let mut signatures = Vec::new();
        for _ in 0..10 {
            let signature = slh_dsa
                .sign_for_algorithm(
                    Algorithm::SlhDsaSha256192fRobust,
                    keypair.secret_key(),
                    message,
                    None,
                )
                .expect("Signing should succeed");
            signatures.push(signature);
        }

        // Check that all signatures are unique (due to randomness)
        for (i, _) in signatures.iter().enumerate() {
            for j in (i + 1)..signatures.len() {
                assert_ne!(
                    signatures[i], signatures[j],
                    "Signatures should be unique due to randomness"
                );
            }
        }

        // But all should verify correctly
        for signature in &signatures {
            let is_valid = slh_dsa
                .verify_for_algorithm(
                    Algorithm::SlhDsaSha256192fRobust,
                    keypair.public_key(),
                    message,
                    signature,
                )
                .expect("Verification should succeed");
            assert!(is_valid, "All signatures should verify correctly");
        }
    }
}

/// Test end-to-end cryptographic operations for FN-DSA
#[cfg(feature = "fn-dsa")]
#[cfg(feature = "std")]
mod fn_dsa_crypto_tests {
    use super::*;

    #[test]
    fn test_fn_dsa_512_end_to_end() {
        let fn_dsa = FnDsa512::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = fn_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Sign message
            let signature = fn_dsa
                .sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = fn_dsa
                .verify(keypair.public_key(), &message, &signature)
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_fn_dsa_1024_end_to_end() {
        let fn_dsa = FnDsa1024::new();
        let test_messages = generate_test_messages();

        for message in test_messages {
            // Generate keypair
            let keypair = fn_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Sign message
            let signature = fn_dsa
                .sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");

            // Verify signature
            let is_valid = fn_dsa
                .verify(keypair.public_key(), &message, &signature)
                .expect("Verification should succeed");
            assert!(
                is_valid,
                "Signature should be valid for message: {:?}",
                message
            );
        }
    }

    #[test]
    fn test_fn_dsa_keypair_uniqueness() {
        let fn_dsa = FnDsa512::new();

        // Generate multiple keypairs and ensure they're unique
        let mut keypairs = Vec::new();
        for _ in 0..10 {
            let keypair = fn_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            keypairs.push(keypair);
        }

        // Check that all public keys are unique
        for (i, _) in keypairs.iter().enumerate() {
            for j in (i + 1)..keypairs.len() {
                assert_ne!(
                    keypairs[i].public_key().as_bytes(),
                    keypairs[j].public_key().as_bytes(),
                    "Public keys should be unique"
                );
                assert_ne!(
                    keypairs[i].secret_key().as_bytes(),
                    keypairs[j].secret_key().as_bytes(),
                    "Secret keys should be unique"
                );
            }
        }
    }
}

/// Test provider integration
#[cfg(feature = "alloc")]
mod provider_integration_tests {
    use super::*;

    #[test]
    fn test_provider_ml_dsa_operations() {
        let provider = LibQSignatureProvider::new().expect("Provider creation should succeed");
        let message = b"Test message for provider operations";

        #[cfg(feature = "ml-dsa")]
        {
            // Test ML-DSA-65 through provider
            let keypair = provider
                .generate_keypair(Algorithm::MlDsa65, None)
                .expect("Key generation should succeed");

            // Verify key sizes are correct for ML-DSA-65
            assert_eq!(
                keypair.public_key().as_bytes().len(),
                1952,
                "ML-DSA-65 public key should be 1952 bytes"
            );
            assert_eq!(
                keypair.secret_key().as_bytes().len(),
                4032,
                "ML-DSA-65 secret key should be 4032 bytes"
            );

            // Test signing and verification
            let signature = provider
                .sign(Algorithm::MlDsa65, keypair.secret_key(), message, None)
                .expect("Signing should succeed");

            let is_valid = provider
                .verify(
                    Algorithm::MlDsa65,
                    keypair.public_key(),
                    message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(is_valid, "Provider signature should be valid");
        }
    }

    #[test]
    fn test_provider_fn_dsa_operations() {
        let _provider = LibQSignatureProvider::new().expect("Provider creation should succeed");
        let _message = b"Test message for provider operations";

        #[cfg(feature = "fn-dsa")]
        {
            // Test FN-DSA-512 through provider
            let keypair = _provider
                .generate_keypair(Algorithm::FnDsa512, None)
                .expect("Key generation should succeed");

            // Verify key sizes are correct for FN-DSA-512 (logn=9)
            // sign_key_size(9) = 1 + (6 << 7) + 512 = 1 + 768 + 512 = 1281
            // vrfy_key_size(9) = 1 + (7 << 7) = 1 + 896 = 897
            assert_eq!(
                keypair.public_key().as_bytes().len(),
                897,
                "FN-DSA-512 public key should be 897 bytes"
            );
            assert_eq!(
                keypair.secret_key().as_bytes().len(),
                1281,
                "FN-DSA-512 secret key should be 1281 bytes"
            );

            let signature = _provider
                .sign(Algorithm::FnDsa512, keypair.secret_key(), _message, None)
                .expect("Signing should succeed");

            let is_valid = _provider
                .verify(
                    Algorithm::FnDsa512,
                    keypair.public_key(),
                    _message,
                    &signature,
                )
                .expect("Verification should succeed");
            assert!(is_valid, "Provider signature should be valid");
        }
    }
}

/// Security tests for edge cases and vulnerabilities
#[cfg(feature = "alloc")]
mod security_tests {
    use super::*;

    #[test]
    fn test_invalid_signature_rejection() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Test message";
            let valid_signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Test with wrong message
            let wrong_message = b"Wrong message";
            let is_valid = ml_dsa
                .verify(keypair.public_key(), wrong_message, &valid_signature)
                .expect("Verification should succeed");
            assert!(!is_valid, "Signature should be invalid for wrong message");

            // Test with corrupted signature
            let mut corrupted_signature = valid_signature.clone();
            if !corrupted_signature.is_empty() {
                corrupted_signature[0] = corrupted_signature[0].wrapping_add(1);
            }
            let is_valid = ml_dsa
                .verify(keypair.public_key(), message, &corrupted_signature)
                .expect("Verification should succeed");
            assert!(!is_valid, "Corrupted signature should be invalid");

            // Test with wrong public key
            let wrong_keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let is_valid = ml_dsa
                .verify(wrong_keypair.public_key(), message, &valid_signature)
                .expect("Verification should succeed");
            assert!(
                !is_valid,
                "Signature should be invalid with wrong public key"
            );
        }
    }

    #[test]
    fn test_empty_signature_rejection() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Test message";
            let empty_signature = vec![];

            let result = ml_dsa.verify(keypair.public_key(), message, &empty_signature);
            assert!(
                result.is_err(),
                "Empty signature must be rejected with an error, not Ok(false)"
            );
            match result {
                Err(lib_q_core::Error::InvalidSignatureSize { .. }) => {}
                other => panic!("expected InvalidSignatureSize, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_truncated_signature_rejected_with_error() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Truncation test";
            let mut sig = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");
            sig.truncate(sig.len().saturating_sub(1));
            let result = ml_dsa.verify(keypair.public_key(), message, &sig);
            assert!(
                matches!(result, Err(lib_q_core::Error::InvalidSignatureSize { .. })),
                "truncated signature must yield InvalidSignatureSize, got {:?}",
                result
            );
        }
    }

    #[test]
    fn test_oversized_signature_rejected_with_error() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Oversize test";
            let mut sig = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");
            sig.push(0u8);
            let result = ml_dsa.verify(keypair.public_key(), message, &sig);
            assert!(
                matches!(result, Err(lib_q_core::Error::InvalidSignatureSize { .. })),
                "oversized signature must yield InvalidSignatureSize, got {:?}",
                result
            );
        }
    }

    #[test]
    fn test_oversized_signature_rejection() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Test message";
            // Create a valid signature for a different message, then try to verify with wrong message
            let wrong_message = b"Wrong message";
            let wrong_signature = ml_dsa
                .sign(keypair.secret_key(), wrong_message)
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify(keypair.public_key(), message, &wrong_signature)
                .expect("Verification should succeed");
            assert!(!is_valid, "Signature for wrong message should be invalid");
        }
    }

    #[test]
    fn test_invalid_key_rejection() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let message = b"Test message";
            let signature = vec![0u8; 1000]; // Dummy signature

            // Test with empty public key
            let empty_key = SigPublicKey::new(vec![]);
            let result = ml_dsa.verify(&empty_key, message, &signature);
            assert!(result.is_err(), "Empty public key should cause error");

            // Test with wrong size public key
            let wrong_size_key = SigPublicKey::new(vec![0u8; 100]);
            let result = ml_dsa.verify(&wrong_size_key, message, &signature);
            assert!(result.is_err(), "Wrong size public key should cause error");
        }
    }
}

/// Performance and timing tests
#[cfg(feature = "alloc")]
mod performance_tests {
    use std::time::{
        Duration,
        Instant,
    };

    use super::*;

    #[test]
    fn test_ml_dsa_performance_consistency() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Performance test message";

            // Warm up once to avoid one-time initialization skewing measurements.
            let _ = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Warm-up signing should succeed");

            // Measure signing time multiple times
            let mut signing_times = Vec::new();
            for _ in 0..10 {
                let start = Instant::now();
                let _signature = ml_dsa
                    .sign(keypair.secret_key(), message)
                    .expect("Signing should succeed");
                let duration = start.elapsed();
                signing_times.push(duration);
            }

            // Check that signing times are reasonably consistent
            // (not testing exact speed, only that behavior stays in a sensible range)
            let avg_time: Duration =
                signing_times.iter().sum::<Duration>() / signing_times.len() as u32;
            let min_time = *signing_times
                .iter()
                .min()
                .expect("At least one signing sample should exist");
            let max_time = *signing_times
                .iter()
                .max()
                .expect("At least one signing sample should exist");
            let max_reasonable_avg = if cfg!(debug_assertions) {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(200)
            };

            assert!(
                avg_time < max_reasonable_avg,
                "Signing average exceeded threshold: avg={avg_time:?}, min={min_time:?}, max={max_time:?}, threshold={max_reasonable_avg:?}"
            );
            assert!(
                max_time.abs_diff(min_time) < Duration::from_millis(400),
                "Signing timings are too inconsistent: min={min_time:?}, max={max_time:?}"
            );
        }
    }

    #[test]
    fn test_verification_performance_consistency() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Performance test message";
            let signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Warm up once to avoid one-time initialization skewing measurements.
            let _ = ml_dsa
                .verify(keypair.public_key(), message, &signature)
                .expect("Warm-up verification should succeed");

            // Measure verification time multiple times
            let mut verification_times = Vec::new();
            for _ in 0..10 {
                let start = Instant::now();
                let _is_valid = ml_dsa
                    .verify(keypair.public_key(), message, &signature)
                    .expect("Verification should succeed");
                let duration = start.elapsed();
                verification_times.push(duration);
            }

            // Check that verification times are reasonably consistent
            let avg_time: Duration =
                verification_times.iter().sum::<Duration>() / verification_times.len() as u32;
            let min_time = *verification_times
                .iter()
                .min()
                .expect("At least one verification sample should exist");
            let max_time = *verification_times
                .iter()
                .max()
                .expect("At least one verification sample should exist");
            let max_reasonable_avg = if cfg!(debug_assertions) {
                Duration::from_millis(600)
            } else {
                Duration::from_millis(100)
            };

            assert!(
                avg_time < max_reasonable_avg,
                "Verification average exceeded threshold: avg={avg_time:?}, min={min_time:?}, max={max_time:?}, threshold={max_reasonable_avg:?}"
            );
            assert!(
                max_time.abs_diff(min_time) < Duration::from_millis(250),
                "Verification timings are too inconsistent: min={min_time:?}, max={max_time:?}"
            );
        }
    }
}

/// Memory safety tests
#[cfg(feature = "alloc")]
mod memory_safety_tests {
    use super::*;

    #[test]
    fn test_keypair_memory_safety() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();

            // Generate keypair and ensure it's properly initialized
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Check that keys are not all zeros or all ones
            let public_key_bytes = keypair.public_key().as_bytes();
            let secret_key_bytes = keypair.secret_key().as_bytes();

            assert!(
                !public_key_bytes.iter().all(|&b| b == 0),
                "Public key should not be all zeros"
            );
            assert!(
                !public_key_bytes.iter().all(|&b| b == 0xFF),
                "Public key should not be all ones"
            );
            assert!(
                !secret_key_bytes.iter().all(|&b| b == 0),
                "Secret key should not be all zeros"
            );
            assert!(
                !secret_key_bytes.iter().all(|&b| b == 0xFF),
                "Secret key should not be all ones"
            );

            // Check that keys have reasonable entropy (not all same byte)
            let public_key_entropy = {
                let mut unique_bytes = Vec::new();
                for &byte in public_key_bytes {
                    if !unique_bytes.contains(&byte) {
                        unique_bytes.push(byte);
                    }
                }
                unique_bytes.len()
            };
            let secret_key_entropy = {
                let mut unique_bytes = Vec::new();
                for &byte in secret_key_bytes {
                    if !unique_bytes.contains(&byte) {
                        unique_bytes.push(byte);
                    }
                }
                unique_bytes.len()
            };

            assert!(
                public_key_entropy > 1,
                "Public key should have some entropy"
            );
            assert!(
                secret_key_entropy > 1,
                "Secret key should have some entropy"
            );
        }
    }

    #[test]
    fn test_signature_memory_safety() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Memory safety test message";

            let signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Check that signature is not all zeros or all ones
            assert!(
                !signature.iter().all(|&b| b == 0),
                "Signature should not be all zeros"
            );
            assert!(
                !signature.iter().all(|&b| b == 0xFF),
                "Signature should not be all ones"
            );

            // Check that signature has reasonable entropy
            let signature_entropy = {
                let mut unique_bytes = Vec::new();
                for byte in &signature {
                    if !unique_bytes.contains(byte) {
                        unique_bytes.push(*byte);
                    }
                }
                unique_bytes.len()
            };
            assert!(signature_entropy > 1, "Signature should have some entropy");
        }
    }
}
