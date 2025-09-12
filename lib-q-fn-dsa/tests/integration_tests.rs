//! Integration tests for FN-DSA implementation
//!
//! These tests verify the integration of FN-DSA with the libQ ecosystem,
//! including algorithm registry, API compatibility, and end-to-end workflows.

#![cfg(test)]

use lib_q_core::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
};
use lib_q_fn_dsa::*;

/// Test basic FN-DSA functionality
#[test]
fn test_basic_fn_dsa_functionality() {
    let fn_dsa = FnDsa512::new();

    // Test keypair generation
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test signing
    let message = b"Hello, FN-DSA!";
    let signature = fn_dsa
        .sign(&keypair.secret_key, message)
        .expect("Signing should succeed");

    // Test verification
    let is_valid = fn_dsa
        .verify(&keypair.public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Signature should be valid");
}

/// Test FN-DSA 1024 functionality
#[test]
fn test_fn_dsa_1024_functionality() {
    let fn_dsa = FnDsa1024::new();

    // Test keypair generation
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test signing
    let message = b"Hello, FN-DSA 1024!";
    let signature = fn_dsa
        .sign(&keypair.secret_key, message)
        .expect("Signing should succeed");

    // Test verification
    let is_valid = fn_dsa
        .verify(&keypair.public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Signature should be valid");
}

/// Test generic FN-DSA functionality
#[test]
fn test_generic_fn_dsa_functionality() {
    // Test Level 1
    let fn_dsa1 = FnDsa::level1();
    assert_eq!(fn_dsa1.security_level(), FnDsaSecurityLevel::Level1);

    let keypair1 = fn_dsa1
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let message = b"Test message";
    let signature1 = fn_dsa1
        .sign(&keypair1.secret_key, message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa1
        .verify(&keypair1.public_key, message, &signature1)
        .expect("Verification should succeed");
    assert!(is_valid, "Level 1 signature should be valid");

    // Test Level 5
    let fn_dsa5 = FnDsa::level5();
    assert_eq!(fn_dsa5.security_level(), FnDsaSecurityLevel::Level5);

    let keypair5 = fn_dsa5
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let signature5 = fn_dsa5
        .sign(&keypair5.secret_key, message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa5
        .verify(&keypair5.public_key, message, &signature5)
        .expect("Verification should succeed");
    assert!(is_valid, "Level 5 signature should be valid");
}

/// Test key serialization and deserialization
#[test]
fn test_key_serialization() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test public key serialization
    let public_key_bytes = keypair.public_key().as_bytes();
    assert!(!public_key_bytes.is_empty(), "Public key should have bytes");

    // Test secret key serialization
    let secret_key_bytes = keypair.secret_key().as_bytes();
    assert!(!secret_key_bytes.is_empty(), "Secret key should have bytes");

    // Test that we can create new key objects from the bytes
    let new_public_key = SigPublicKey::new(public_key_bytes.to_vec());
    let new_secret_key = SigSecretKey::new(secret_key_bytes.to_vec());

    // Test that the new keys work
    let message = b"Test message";
    let signature = fn_dsa
        .sign(&new_secret_key, message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa
        .verify(&new_public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Deserialized keys should work");
}

/// Test signature serialization
#[test]
fn test_signature_serialization() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let message = b"Test message";

    // Generate signature
    let signature = fn_dsa
        .sign(&keypair.secret_key, message)
        .expect("Signing should succeed");

    // Test signature serialization
    let signature_bytes = signature.as_slice();
    assert!(!signature_bytes.is_empty(), "Signature should have bytes");

    // Test that we can verify the serialized signature
    let is_valid = fn_dsa
        .verify(&keypair.public_key, message, signature_bytes)
        .expect("Verification should succeed");
    assert!(is_valid, "Serialized signature should be valid");
}

/// Test multiple message signing
#[test]
fn test_multiple_message_signing() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    let messages: Vec<&[u8]> = vec![
        b"First message",
        b"Second message",
        b"Third message",
        b"",
        b"A very long message that contains multiple words and should test the signing algorithm with different message lengths",
    ];

    for message in messages {
        let signature = fn_dsa
            .sign(&keypair.secret_key, message)
            .expect("Signing should succeed");
        let is_valid = fn_dsa
            .verify(&keypair.public_key, message, &signature)
            .expect("Verification should succeed");
        assert!(
            is_valid,
            "Signature should be valid for message: {:?}",
            message
        );
    }
}

/// Test cross-key verification (should fail)
#[test]
fn test_cross_key_verification() {
    let fn_dsa = FnDsa512::new();
    let keypair1 = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let keypair2 = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    let message = b"Test message";
    let signature = fn_dsa
        .sign(&keypair1.secret_key, message)
        .expect("Signing should succeed");

    // Verify with correct public key (should succeed)
    let is_valid = fn_dsa
        .verify(&keypair1.public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(
        is_valid,
        "Signature should be valid with correct public key"
    );

    // Verify with different public key (should fail)
    let is_valid = fn_dsa
        .verify(&keypair2.public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(
        !is_valid,
        "Signature should be invalid with different public key"
    );
}

/// Test algorithm consistency
#[test]
fn test_algorithm_consistency() {
    let fn_dsa1 = FnDsa512::new();
    let fn_dsa2 = FnDsa512::new();

    // Both instances should have the same security level
    assert_eq!(fn_dsa1.security_level(), fn_dsa2.security_level());
    assert_eq!(fn_dsa1.logn(), fn_dsa2.logn());

    // Both instances should produce the same key sizes
    let keypair1 = fn_dsa1
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let keypair2 = fn_dsa2
        .generate_keypair()
        .expect("Keypair generation should succeed");

    assert_eq!(
        keypair1.public_key().as_bytes().len(),
        keypair2.public_key().as_bytes().len()
    );
    assert_eq!(
        keypair1.secret_key().as_bytes().len(),
        keypair2.secret_key().as_bytes().len()
    );
}

/// Test error propagation
#[test]
fn test_error_propagation() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test with invalid secret key size
    let invalid_secret_key = SigSecretKey::new(vec![0u8; 1000]);
    let result = fn_dsa.sign(&invalid_secret_key, b"test");
    assert!(
        result.is_err(),
        "Signing should fail with invalid secret key size"
    );

    // Test with invalid public key size
    let invalid_public_key = SigPublicKey::new(vec![0u8; 1000]);
    let signature = fn_dsa
        .sign(&keypair.secret_key, b"test")
        .expect("Signing should succeed");
    let result = fn_dsa.verify(&invalid_public_key, b"test", &signature);
    assert!(
        result.is_err(),
        "Verification should fail with invalid public key size"
    );
}

/// Test performance characteristics
#[test]
fn test_performance_characteristics() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");
    let message = b"Performance test message";

    // Test signing performance
    let start = std::time::Instant::now();
    let signature = fn_dsa
        .sign(&keypair.secret_key, message)
        .expect("Signing should succeed");
    let sign_duration = start.elapsed();

    // Test verification performance
    let start = std::time::Instant::now();
    let is_valid = fn_dsa
        .verify(&keypair.public_key, message, &signature)
        .expect("Verification should succeed");
    let verify_duration = start.elapsed();

    assert!(is_valid, "Signature should be valid");

    // Basic performance checks (these are not strict requirements,
    // but help ensure the implementation is reasonable)
    assert!(
        sign_duration.as_millis() < 1000,
        "Signing should complete within 1 second"
    );
    assert!(
        verify_duration.as_millis() < 1000,
        "Verification should complete within 1 second"
    );

    println!("Signing time: {:?}", sign_duration);
    println!("Verification time: {:?}", verify_duration);
}

/// Test memory usage
#[test]
fn test_memory_usage() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test that key sizes are as expected
    let expected_public_key_size = vrfy_key_size(FN_DSA_LOGN_512);
    let expected_secret_key_size = sign_key_size(FN_DSA_LOGN_512);

    assert_eq!(
        keypair.public_key().as_bytes().len(),
        expected_public_key_size
    );
    assert_eq!(
        keypair.secret_key().as_bytes().len(),
        expected_secret_key_size
    );

    // Test signature size
    let message = b"Memory test message";
    let signature = fn_dsa
        .sign(&keypair.secret_key, message)
        .expect("Signing should succeed");
    let expected_signature_size = signature_size(FN_DSA_LOGN_512);

    assert_eq!(signature.len(), expected_signature_size);
}

/// Test SigKeypair functionality
#[test]
fn test_sig_keypair_functionality() {
    let fn_dsa = FnDsa512::new();

    // Test keypair generation
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test that keypair contains both keys
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();

    assert!(
        !public_key.as_bytes().is_empty(),
        "Public key should not be empty"
    );
    assert!(
        !secret_key.as_bytes().is_empty(),
        "Secret key should not be empty"
    );

    // Test that keys have expected sizes
    let expected_public_key_size = vrfy_key_size(FN_DSA_LOGN_512);
    let expected_secret_key_size = sign_key_size(FN_DSA_LOGN_512);

    assert_eq!(
        public_key.as_bytes().len(),
        expected_public_key_size,
        "Public key should have expected size"
    );
    assert_eq!(
        secret_key.as_bytes().len(),
        expected_secret_key_size,
        "Secret key should have expected size"
    );

    // Test that the keypair works for signing and verification
    let message = b"Test message for keypair functionality";
    let signature = fn_dsa
        .sign(secret_key, message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa
        .verify(public_key, message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Signature should be valid");

    // Test keypair creation from individual keys
    let public_key_bytes = public_key.as_bytes().to_vec();
    let secret_key_bytes = secret_key.as_bytes().to_vec();
    let reconstructed_keypair = SigKeypair::new(public_key_bytes, secret_key_bytes);

    // Test that reconstructed keypair works
    let signature2 = fn_dsa
        .sign(reconstructed_keypair.secret_key(), message)
        .expect("Signing should succeed");
    let is_valid2 = fn_dsa
        .verify(reconstructed_keypair.public_key(), message, &signature2)
        .expect("Verification should succeed");
    assert!(is_valid2, "Reconstructed keypair should work");

    // Test that both keypairs produce the same signature (deterministic)
    // Note: FN-DSA signatures are non-deterministic due to randomness,
    // so we just verify both signatures are valid
    assert!(
        is_valid && is_valid2,
        "Both keypairs should produce valid signatures"
    );
}

/// Test SigKeypair with different security levels
#[test]
fn test_sig_keypair_security_levels() {
    // Test Level 1 (512-bit)
    let fn_dsa512 = FnDsa512::new();
    let keypair512 = fn_dsa512
        .generate_keypair()
        .expect("Keypair generation should succeed");

    let expected_public_key_size_512 = vrfy_key_size(FN_DSA_LOGN_512);
    let expected_secret_key_size_512 = sign_key_size(FN_DSA_LOGN_512);

    assert_eq!(
        keypair512.public_key().as_bytes().len(),
        expected_public_key_size_512,
        "512-bit public key should have expected size"
    );
    assert_eq!(
        keypair512.secret_key().as_bytes().len(),
        expected_secret_key_size_512,
        "512-bit secret key should have expected size"
    );

    // Test Level 5 (1024-bit)
    let fn_dsa1024 = FnDsa1024::new();
    let keypair1024 = fn_dsa1024
        .generate_keypair()
        .expect("Keypair generation should succeed");

    let expected_public_key_size_1024 = vrfy_key_size(FN_DSA_LOGN_1024);
    let expected_secret_key_size_1024 = sign_key_size(FN_DSA_LOGN_1024);

    assert_eq!(
        keypair1024.public_key().as_bytes().len(),
        expected_public_key_size_1024,
        "1024-bit public key should have expected size"
    );
    assert_eq!(
        keypair1024.secret_key().as_bytes().len(),
        expected_secret_key_size_1024,
        "1024-bit secret key should have expected size"
    );

    // Test that 1024-bit keys are larger than 512-bit keys
    assert!(
        keypair1024.public_key().as_bytes().len() > keypair512.public_key().as_bytes().len(),
        "1024-bit public key should be larger than 512-bit public key"
    );
    assert!(
        keypair1024.secret_key().as_bytes().len() > keypair512.secret_key().as_bytes().len(),
        "1024-bit secret key should be larger than 512-bit secret key"
    );

    // Test that both keypairs work for their respective algorithms
    let message = b"Test message for security level comparison";

    let signature512 = fn_dsa512
        .sign(keypair512.secret_key(), message)
        .expect("512-bit signing should succeed");
    let is_valid512 = fn_dsa512
        .verify(keypair512.public_key(), message, &signature512)
        .expect("512-bit verification should succeed");
    assert!(is_valid512, "512-bit signature should be valid");

    let signature1024 = fn_dsa1024
        .sign(keypair1024.secret_key(), message)
        .expect("1024-bit signing should succeed");
    let is_valid1024 = fn_dsa1024
        .verify(keypair1024.public_key(), message, &signature1024)
        .expect("1024-bit verification should succeed");
    assert!(is_valid1024, "1024-bit signature should be valid");
}

/// Test edge cases
#[test]
fn test_edge_cases() {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa
        .generate_keypair()
        .expect("Keypair generation should succeed");

    // Test with empty message
    let empty_message = b"";
    let signature = fn_dsa
        .sign(&keypair.secret_key, empty_message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa
        .verify(&keypair.public_key, empty_message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Empty message signature should be valid");

    // Test with single byte message
    let single_byte_message = b"a";
    let signature = fn_dsa
        .sign(&keypair.secret_key, single_byte_message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa
        .verify(&keypair.public_key, single_byte_message, &signature)
        .expect("Verification should succeed");
    assert!(is_valid, "Single byte message signature should be valid");

    // Test with message containing null bytes
    let null_message = b"Message with\0null bytes";
    let signature = fn_dsa
        .sign(&keypair.secret_key, null_message)
        .expect("Signing should succeed");
    let is_valid = fn_dsa
        .verify(&keypair.public_key, null_message, &signature)
        .expect("Verification should succeed");
    assert!(
        is_valid,
        "Message with null bytes signature should be valid"
    );
}
