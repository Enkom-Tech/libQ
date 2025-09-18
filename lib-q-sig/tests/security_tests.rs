//! Security tests for lib-q-sig
//!
//! This module provides comprehensive security testing including:
//! - Timing attack resistance tests
//! - Side-channel attack resistance tests
//! - Input validation security tests
//! - Memory safety and zeroization tests
//! - Cryptographic strength tests

#[cfg(feature = "alloc")]
extern crate alloc;

use std::time::{
    Duration,
    Instant,
};

use lib_q_core::{
    Error,
    SigPublicKey,
    Signature,
};
#[cfg(feature = "fn-dsa")]
use lib_q_sig::fn_dsa::{
    FnDsa512,
    FnDsa1024,
};
use lib_q_sig::ml_dsa::MlDsa;

/// Test timing attack resistance
#[cfg(feature = "alloc")]
mod timing_attack_tests {
    use super::*;

    #[test]
    fn test_verification_timing_consistency() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Timing attack test message";
            let valid_signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Create invalid signatures of different types
            let mut invalid_signature = valid_signature.clone();
            if !invalid_signature.is_empty() {
                invalid_signature[0] = invalid_signature[0].wrapping_add(1);
            }
            let empty_signature = vec![];
            // Create a signature for a different message (wrong signature)
            let wrong_message = b"Wrong message";
            let wrong_signature = ml_dsa
                .sign(keypair.secret_key(), wrong_message)
                .expect("Signing should succeed");

            // Measure verification times for valid and invalid signatures
            let valid_times = measure_verification_times(
                &ml_dsa,
                keypair.public_key(),
                message,
                &valid_signature,
                100,
            );
            let invalid_times = measure_verification_times(
                &ml_dsa,
                keypair.public_key(),
                message,
                &invalid_signature,
                100,
            );
            let empty_times = measure_verification_times(
                &ml_dsa,
                keypair.public_key(),
                message,
                &empty_signature,
                100,
            );
            let wrong_times = measure_verification_times(
                &ml_dsa,
                keypair.public_key(),
                message,
                &wrong_signature,
                100,
            );

            // Check that timing differences are not significant
            // (This is a basic test - in practice, more sophisticated statistical analysis would be needed)
            let valid_avg = average_duration(&valid_times);
            let invalid_avg = average_duration(&invalid_times);
            let empty_avg = average_duration(&empty_times);
            let wrong_avg = average_duration(&wrong_times);

            // Allow for some timing variation but ensure it's not too large
            let max_variation = Duration::from_micros(1000); // 1ms
            let diff1 = valid_avg.abs_diff(invalid_avg);
            let diff2 = valid_avg.abs_diff(empty_avg);
            let diff3 = valid_avg.abs_diff(wrong_avg);

            assert!(
                diff1 < max_variation,
                "Timing difference between valid and invalid signatures should be minimal"
            );
            assert!(
                diff2 < max_variation,
                "Timing difference between valid and empty signatures should be minimal"
            );
            assert!(
                diff3 < max_variation,
                "Timing difference between valid and wrong signatures should be minimal"
            );
        }
    }

    #[test]
    fn test_key_validation_timing_consistency() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let valid_keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Key validation timing test";
            let signature = ml_dsa
                .sign(valid_keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Create invalid keys of different types
            let empty_key = SigPublicKey::new(vec![]);
            let wrong_size_key = SigPublicKey::new(vec![0u8; 100]);
            let all_zeros_key = SigPublicKey::new(vec![0u8; 1952]); // ML-DSA-65 public key size
            let all_ones_key = SigPublicKey::new(vec![0xFFu8; 1952]);

            // Measure verification times for valid and invalid keys
            let valid_times = measure_verification_times(
                &ml_dsa,
                valid_keypair.public_key(),
                message,
                &signature,
                100,
            );
            let empty_times =
                measure_verification_times(&ml_dsa, &empty_key, message, &signature, 100);
            let wrong_size_times =
                measure_verification_times(&ml_dsa, &wrong_size_key, message, &signature, 100);
            let all_zeros_times =
                measure_verification_times(&ml_dsa, &all_zeros_key, message, &signature, 100);
            let all_ones_times =
                measure_verification_times(&ml_dsa, &all_ones_key, message, &signature, 100);

            // Check that timing differences are not significant
            let valid_avg = average_duration(&valid_times);
            let empty_avg = average_duration(&empty_times);
            let wrong_size_avg = average_duration(&wrong_size_times);
            let all_zeros_avg = average_duration(&all_zeros_times);
            let all_ones_avg = average_duration(&all_ones_times);

            let max_variation = Duration::from_micros(1000); // 1ms
            let diff1 = valid_avg.abs_diff(empty_avg);
            let diff2 = valid_avg.abs_diff(wrong_size_avg);
            let diff3 = valid_avg.abs_diff(all_zeros_avg);
            let diff4 = valid_avg.abs_diff(all_ones_avg);

            assert!(
                diff1 < max_variation,
                "Timing difference between valid and empty keys should be minimal"
            );
            assert!(
                diff2 < max_variation,
                "Timing difference between valid and wrong size keys should be minimal"
            );
            assert!(
                diff3 < max_variation,
                "Timing difference between valid and all zeros keys should be minimal"
            );
            assert!(
                diff4 < max_variation,
                "Timing difference between valid and all ones keys should be minimal"
            );
        }
    }

    fn measure_verification_times(
        ml_dsa: &MlDsa,
        public_key: &SigPublicKey,
        message: &[u8],
        signature: &[u8],
        iterations: usize,
    ) -> Vec<Duration> {
        let mut times = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = ml_dsa.verify(public_key, message, signature);
            let duration = start.elapsed();
            times.push(duration);
        }

        times
    }

    fn average_duration(durations: &[Duration]) -> Duration {
        let total: Duration = durations.iter().sum();
        total / durations.len() as u32
    }
}

/// Test input validation security
#[cfg(feature = "alloc")]
mod input_validation_tests {
    use super::*;

    #[test]
    fn test_malicious_input_handling() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Test with extremely large messages
            let large_message = vec![0u8; 10 * 1024 * 1024]; // 10MB
            let result = ml_dsa.sign(keypair.secret_key(), &large_message);
            // Should either succeed or fail gracefully, not panic
            match result {
                Ok(signature) => {
                    // If it succeeds, verification should also work
                    let is_valid = ml_dsa
                        .verify(keypair.public_key(), &large_message, &signature)
                        .expect("Verification should succeed");
                    assert!(is_valid, "Large message signature should be valid");
                }
                Err(_) => {
                    // If it fails, it should be a proper error, not a panic
                }
            }
        }
    }

    #[test]
    fn test_null_byte_handling() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Test with messages containing null bytes
            let null_message = b"Hello\0World\0Test";
            let signature = ml_dsa
                .sign(keypair.secret_key(), null_message)
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify(keypair.public_key(), null_message, &signature)
                .expect("Verification should succeed");
            assert!(is_valid, "Null byte message should be handled correctly");
        }
    }

    #[test]
    fn test_unicode_handling() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Test with Unicode messages
            let unicode_message = "Hello, 世界! 🌍".as_bytes();
            let signature = ml_dsa
                .sign(keypair.secret_key(), unicode_message)
                .expect("Signing should succeed");

            let is_valid = ml_dsa
                .verify(keypair.public_key(), unicode_message, &signature)
                .expect("Verification should succeed");
            assert!(is_valid, "Unicode message should be handled correctly");
        }
    }

    #[test]
    fn test_boundary_condition_handling() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Test with boundary conditions
            let boundary_messages = vec![
                vec![],            // Empty message
                vec![0u8; 1],      // Single byte
                vec![0xFFu8; 1],   // Single 0xFF byte
                vec![0u8; 255],    // 255 bytes
                vec![0xFFu8; 255], // 255 0xFF bytes
            ];

            for message in boundary_messages {
                let signature = ml_dsa
                    .sign(keypair.secret_key(), &message)
                    .expect("Signing should succeed");

                let is_valid = ml_dsa
                    .verify(keypair.public_key(), &message, &signature)
                    .expect("Verification should succeed");
                assert!(
                    is_valid,
                    "Boundary condition message should be handled correctly"
                );
            }
        }
    }
}

/// Test cryptographic strength
#[cfg(feature = "alloc")]
mod cryptographic_strength_tests {
    use super::*;

    #[test]
    fn test_key_uniqueness() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();

            // Generate many keypairs and ensure they're all unique
            let mut public_keys = Vec::new();
            let mut secret_keys = Vec::new();

            for _ in 0..1000 {
                let keypair = ml_dsa
                    .generate_keypair()
                    .expect("Key generation should succeed");

                // Check public key uniqueness
                let public_key_bytes = keypair.public_key().as_bytes();
                assert!(
                    !public_keys.contains(&public_key_bytes.to_vec()),
                    "Public keys should be unique"
                );
                public_keys.push(public_key_bytes.to_vec());

                // Check secret key uniqueness
                let secret_key_bytes = keypair.secret_key().as_bytes();
                assert!(
                    !secret_keys.contains(&secret_key_bytes.to_vec()),
                    "Secret keys should be unique"
                );
                secret_keys.push(secret_key_bytes.to_vec());
            }
        }
    }

    #[test]
    fn test_signature_uniqueness() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Signature uniqueness test message";

            // Generate many signatures and ensure they're all unique
            let mut signatures = Vec::new();

            for _ in 0..1000 {
                let signature = ml_dsa
                    .sign(keypair.secret_key(), message)
                    .expect("Signing should succeed");

                assert!(
                    !signatures.contains(&signature),
                    "Signatures should be unique due to randomness"
                );
                signatures.push(signature);
            }
        }
    }

    #[test]
    fn test_cross_algorithm_security() {
        // Test that signatures from one algorithm don't validate with another
        #[cfg(all(feature = "ml-dsa", feature = "fn-dsa"))]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let fn_dsa = FnDsa512::new();

            let ml_keypair = ml_dsa
                .generate_keypair()
                .expect("ML-DSA key generation should succeed");
            let fn_keypair = fn_dsa
                .generate_keypair()
                .expect("FN-DSA key generation should succeed");

            let message = b"Cross-algorithm security test";

            // Sign with ML-DSA
            let ml_signature = ml_dsa
                .sign(ml_keypair.secret_key(), message)
                .expect("ML-DSA signing should succeed");

            // Sign with FN-DSA
            let fn_signature = fn_dsa
                .sign(fn_keypair.secret_key(), message)
                .expect("FN-DSA signing should succeed");

            // ML-DSA signature should not validate with FN-DSA
            // This will likely fail due to signature size mismatch, which is expected
            let result = fn_dsa.verify(fn_keypair.public_key(), message, &ml_signature);
            match result {
                Ok(false) => {
                    // Valid response - signature rejected
                }
                Err(_) => {
                    // Valid error response - signature size mismatch or other validation error
                }
                Ok(true) => {
                    panic!("ML-DSA signature should not validate with FN-DSA");
                }
            }

            // FN-DSA signature should not validate with ML-DSA
            // This will likely fail due to signature size mismatch, which is expected
            let result = ml_dsa.verify(ml_keypair.public_key(), message, &fn_signature);
            match result {
                Ok(false) => {
                    // Valid response - signature rejected
                }
                Err(_) => {
                    // Valid error response - signature size mismatch or other validation error
                }
                Ok(true) => {
                    panic!("FN-DSA signature should not validate with ML-DSA");
                }
            }
        }
    }

    #[test]
    fn test_key_entropy_quality() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();

            // Generate multiple keypairs and check entropy quality
            for _ in 0..100 {
                let keypair = ml_dsa
                    .generate_keypair()
                    .expect("Key generation should succeed");

                let public_key_bytes = keypair.public_key().as_bytes();
                let secret_key_bytes = keypair.secret_key().as_bytes();

                // Check that keys have good entropy (not all same byte)
                let public_entropy = {
                    let mut unique_bytes = Vec::new();
                    for &byte in public_key_bytes {
                        if !unique_bytes.contains(&byte) {
                            unique_bytes.push(byte);
                        }
                    }
                    unique_bytes.len()
                };
                let secret_entropy = {
                    let mut unique_bytes = Vec::new();
                    for &byte in secret_key_bytes {
                        if !unique_bytes.contains(&byte) {
                            unique_bytes.push(byte);
                        }
                    }
                    unique_bytes.len()
                };

                assert!(public_entropy > 10, "Public key should have good entropy");
                assert!(secret_entropy > 10, "Secret key should have good entropy");

                // Check that keys are not all zeros or all ones
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
            }
        }
    }
}

/// Test memory safety and zeroization
#[cfg(feature = "alloc")]
mod memory_safety_tests {
    use super::*;

    #[test]
    fn test_sensitive_data_handling() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();

            // Generate keypair and check that sensitive data is properly handled
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Check that secret key is not exposed in public key
            let public_key_bytes = keypair.public_key().as_bytes();
            let secret_key_bytes = keypair.secret_key().as_bytes();

            // Public and secret keys should be different
            assert_ne!(
                public_key_bytes, secret_key_bytes,
                "Public and secret keys should be different"
            );

            // Secret key should not be a subset of public key
            assert!(
                !public_key_bytes
                    .windows(secret_key_bytes.len())
                    .any(|window| window == secret_key_bytes),
                "Secret key should not be contained in public key"
            );
        }
    }

    #[test]
    fn test_memory_layout_security() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");

            // Check that key data is properly aligned and sized
            let public_key_bytes = keypair.public_key().as_bytes();
            let secret_key_bytes = keypair.secret_key().as_bytes();

            // Check expected sizes for ML-DSA-65
            assert_eq!(
                public_key_bytes.len(),
                1952,
                "Public key should have correct size"
            );
            assert_eq!(
                secret_key_bytes.len(),
                4032,
                "Secret key should have correct size"
            );

            // Check that keys are not uninitialized memory
            assert!(
                !public_key_bytes.iter().all(|&b| b == 0),
                "Public key should not be uninitialized"
            );
            assert!(
                !secret_key_bytes.iter().all(|&b| b == 0),
                "Secret key should not be uninitialized"
            );
        }
    }
}

/// Test error handling security
#[cfg(feature = "alloc")]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_message_security() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();
            let keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let message = b"Error message security test";
            let signature = ml_dsa
                .sign(keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Test with invalid public key
            let invalid_key = SigPublicKey::new(vec![0u8; 100]);
            let result = ml_dsa.verify(&invalid_key, message, &signature);

            // Error should not leak sensitive information
            match result {
                Err(Error::InvalidKeySize { expected, actual }) => {
                    assert_eq!(expected, 1952, "Should report correct expected key size");
                    assert_eq!(actual, 100, "Should report correct actual key size");
                }
                Err(e) => {
                    // Other errors are also acceptable, as long as they don't leak sensitive data
                    let error_msg = format!("{:?}", e);
                    assert!(
                        !error_msg.contains("secret"),
                        "Error should not leak secret information"
                    );
                    assert!(
                        !error_msg.contains("private"),
                        "Error should not leak private information"
                    );
                }
                Ok(_) => {
                    panic!("Invalid key should cause error");
                }
            }
        }
    }

    #[test]
    fn test_graceful_degradation() {
        #[cfg(feature = "ml-dsa")]
        {
            let ml_dsa = MlDsa::ml_dsa_65();

            // Test that the system fails gracefully under various error conditions
            let invalid_keys = vec![
                // Invalid key sizes
                SigPublicKey::new(vec![]),
                SigPublicKey::new(vec![0u8; 1]),
                SigPublicKey::new(vec![0u8; 10000]),
            ];

            let message = b"Graceful degradation test";
            let valid_keypair = ml_dsa
                .generate_keypair()
                .expect("Key generation should succeed");
            let valid_signature = ml_dsa
                .sign(valid_keypair.secret_key(), message)
                .expect("Signing should succeed");

            // Create invalid signatures
            let invalid_signatures: Vec<Vec<u8>> = vec![
                // Invalid signature sizes
                vec![],
                vec![0u8; 1],
                vec![0u8; 100], // Small but valid size signature
            ];

            // Test invalid keys
            for invalid_key in invalid_keys {
                // Should not panic, should return proper error
                let result = ml_dsa.verify(&invalid_key, message, &valid_signature);

                // Should either return an error or false, but not panic
                match result {
                    Ok(false) => {
                        // Valid response for invalid input
                    }
                    Err(_) => {
                        // Valid error response
                    }
                    Ok(true) => {
                        panic!("Invalid key should not return true");
                    }
                }
            }

            // Test invalid signatures
            for invalid_signature in invalid_signatures {
                // Should not panic, should return proper error
                let result = ml_dsa.verify(valid_keypair.public_key(), message, &invalid_signature);

                // Should either return an error or false, but not panic
                match result {
                    Ok(false) => {
                        // Valid response for invalid input
                    }
                    Err(_) => {
                        // Valid error response
                    }
                    Ok(true) => {
                        panic!("Invalid signature should not return true");
                    }
                }
            }
        }
    }
}
