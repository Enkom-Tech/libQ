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

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

/// Test basic FN-DSA functionality
#[test]
fn test_basic_fn_dsa_functionality() -> TestResult {
    let fn_dsa = FnDsa512::new();
    assert_eq!(fn_dsa.security_level(), FnDsaSecurityLevel::Level1);
    assert_eq!(fn_dsa.logn(), FN_DSA_LOGN_512);

    let keypair = fn_dsa.generate_keypair()?;
    let expected_sizes = FnDsaSecurityLevel::Level1.key_sizes();
    assert_eq!(keypair.secret_key.as_bytes().len(), expected_sizes.0);
    assert_eq!(keypair.public_key.as_bytes().len(), expected_sizes.1);

    let message = b"Hello, FN-DSA!";
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    assert_eq!(signature.len(), expected_sizes.2);

    let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    assert!(is_valid, "Signature should be valid");

    let wrong_message_valid = fn_dsa.verify(&keypair.public_key, b"wrong message", &signature)?;
    assert!(
        !wrong_message_valid,
        "Signature should fail for wrong message"
    );

    let generic_level1 = FnDsa::level1();
    assert_eq!(generic_level1.security_level(), FnDsaSecurityLevel::Level1);
    assert_eq!(generic_level1.logn(), FN_DSA_LOGN_512);
    assert!(generic_level1.verify(&keypair.public_key, message, &signature)?);

    let default_fn_dsa = FnDsa::default();
    assert_eq!(default_fn_dsa.security_level(), FnDsaSecurityLevel::Level1);
    assert!(default_fn_dsa.verify(&keypair.public_key, message, &signature)?);

    let fn_dsa_1024 = FnDsa1024::default();
    assert_eq!(fn_dsa_1024.security_level(), FnDsaSecurityLevel::Level5);
    assert_eq!(fn_dsa_1024.logn(), FN_DSA_LOGN_1024);

    let keypair_1024 = fn_dsa_1024.generate_keypair()?;
    let message_1024 = b"Hello, FN-DSA 1024!";
    let signature_1024 = fn_dsa_1024.sign(&keypair_1024.secret_key, message_1024)?;
    assert!(fn_dsa_1024.verify(&keypair_1024.public_key, message_1024, &signature_1024)?);

    let generic_level5 = FnDsa::level5();
    assert_eq!(generic_level5.security_level(), FnDsaSecurityLevel::Level5);
    assert_eq!(generic_level5.logn(), FN_DSA_LOGN_1024);
    assert!(generic_level5.verify(&keypair_1024.public_key, message_1024, &signature_1024)?);

    let invalid_1024_sig = vec![0_u8; signature_size(FN_DSA_LOGN_1024) - 1];
    let invalid_sig_result =
        generic_level5.verify(&keypair_1024.public_key, message_1024, &invalid_1024_sig);
    assert!(matches!(
        invalid_sig_result,
        Err(Error::InvalidSignatureSize {
            expected,
            actual
        }) if expected == signature_size(FN_DSA_LOGN_1024)
            && actual == signature_size(FN_DSA_LOGN_1024) - 1
    ));

    let invalid_sign_size = utils::validate_key_sizes(
        FnDsaSecurityLevel::Level1,
        expected_sizes.0 - 1,
        expected_sizes.1,
        expected_sizes.2,
    );
    assert!(matches!(
        invalid_sign_size,
        Err(Error::InvalidKeySize { expected, actual }) if expected == expected_sizes.0
            && actual == expected_sizes.0 - 1
    ));

    let invalid_vrfy_size = utils::validate_key_sizes(
        FnDsaSecurityLevel::Level1,
        expected_sizes.0,
        expected_sizes.1 - 1,
        expected_sizes.2,
    );
    assert!(matches!(
        invalid_vrfy_size,
        Err(Error::InvalidKeySize { expected, actual }) if expected == expected_sizes.1
            && actual == expected_sizes.1 - 1
    ));

    let invalid_sig_size = utils::validate_key_sizes(
        FnDsaSecurityLevel::Level1,
        expected_sizes.0,
        expected_sizes.1,
        expected_sizes.2 - 1,
    );
    assert!(matches!(
        invalid_sig_size,
        Err(Error::InvalidKeySize { expected, actual }) if expected == expected_sizes.2
            && actual == expected_sizes.2 - 1
    ));

    let level5_sizes = utils::get_key_sizes(FnDsaSecurityLevel::Level5);
    assert_eq!(level5_sizes.0, sign_key_size(FN_DSA_LOGN_1024));
    assert_eq!(level5_sizes.1, vrfy_key_size(FN_DSA_LOGN_1024));
    assert_eq!(level5_sizes.2, signature_size(FN_DSA_LOGN_1024));

    utils::validate_key_sizes(
        FnDsaSecurityLevel::Level5,
        level5_sizes.0,
        level5_sizes.1,
        level5_sizes.2,
    )?;
    Ok(())
}

/// Test FN-DSA 1024 functionality
#[test]
fn test_fn_dsa_1024_functionality() -> TestResult {
    let fn_dsa = FnDsa1024::new();

    let keypair = fn_dsa.generate_keypair()?;

    let message = b"Hello, FN-DSA 1024!";
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;

    let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    assert!(is_valid, "Signature should be valid");
    Ok(())
}

/// Test generic FN-DSA functionality
#[test]
fn test_generic_fn_dsa_functionality() -> TestResult {
    let fn_dsa1 = FnDsa::level1();
    assert_eq!(fn_dsa1.security_level(), FnDsaSecurityLevel::Level1);

    let keypair1 = fn_dsa1.generate_keypair()?;
    let message = b"Test message";
    let signature1 = fn_dsa1.sign(&keypair1.secret_key, message)?;
    let is_valid = fn_dsa1.verify(&keypair1.public_key, message, &signature1)?;
    assert!(is_valid, "Level 1 signature should be valid");

    let fn_dsa5 = FnDsa::level5();
    assert_eq!(fn_dsa5.security_level(), FnDsaSecurityLevel::Level5);

    let keypair5 = fn_dsa5.generate_keypair()?;
    let signature5 = fn_dsa5.sign(&keypair5.secret_key, message)?;
    let is_valid = fn_dsa5.verify(&keypair5.public_key, message, &signature5)?;
    assert!(is_valid, "Level 5 signature should be valid");
    Ok(())
}

/// Test key serialization and deserialization
#[test]
fn test_key_serialization() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let public_key_bytes = keypair.public_key().as_bytes();
    assert!(!public_key_bytes.is_empty(), "Public key should have bytes");

    let secret_key_bytes = keypair.secret_key().as_bytes();
    assert!(!secret_key_bytes.is_empty(), "Secret key should have bytes");

    let new_public_key = SigPublicKey::new(public_key_bytes.to_vec());
    let new_secret_key = SigSecretKey::new(secret_key_bytes.to_vec());

    let message = b"Test message";
    let signature = fn_dsa.sign(&new_secret_key, message)?;
    let is_valid = fn_dsa.verify(&new_public_key, message, &signature)?;
    assert!(is_valid, "Deserialized keys should work");
    Ok(())
}

/// Test signature serialization
#[test]
fn test_signature_serialization() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;
    let message = b"Test message";

    let signature = fn_dsa.sign(&keypair.secret_key, message)?;

    let signature_bytes = signature.as_slice();
    assert!(!signature_bytes.is_empty(), "Signature should have bytes");

    let is_valid = fn_dsa.verify(&keypair.public_key, message, signature_bytes)?;
    assert!(is_valid, "Serialized signature should be valid");
    Ok(())
}

/// Test multiple message signing
#[test]
fn test_multiple_message_signing() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let messages: Vec<&[u8]> = vec![
        b"First message",
        b"Second message",
        b"Third message",
        b"",
        b"A very long message that contains multiple words and should test the signing algorithm with different message lengths",
    ];

    for message in messages {
        let signature = fn_dsa.sign(&keypair.secret_key, message)?;
        let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
        assert!(
            is_valid,
            "Signature should be valid for message: {:?}",
            message
        );
    }
    Ok(())
}

/// Test cross-key verification (should fail)
#[test]
fn test_cross_key_verification() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair1 = fn_dsa.generate_keypair()?;
    let keypair2 = fn_dsa.generate_keypair()?;

    let message = b"Test message";
    let signature = fn_dsa.sign(&keypair1.secret_key, message)?;

    let is_valid = fn_dsa.verify(&keypair1.public_key, message, &signature)?;
    assert!(
        is_valid,
        "Signature should be valid with correct public key"
    );

    let is_valid = fn_dsa.verify(&keypair2.public_key, message, &signature)?;
    assert!(
        !is_valid,
        "Signature should be invalid with different public key"
    );
    Ok(())
}

/// Test algorithm consistency
#[test]
fn test_algorithm_consistency() -> TestResult {
    let fn_dsa1 = FnDsa512::new();
    let fn_dsa2 = FnDsa512::new();

    assert_eq!(fn_dsa1.security_level(), fn_dsa2.security_level());
    assert_eq!(fn_dsa1.logn(), fn_dsa2.logn());

    let keypair1 = fn_dsa1.generate_keypair()?;
    let keypair2 = fn_dsa2.generate_keypair()?;

    assert_eq!(
        keypair1.public_key().as_bytes().len(),
        keypair2.public_key().as_bytes().len()
    );
    assert_eq!(
        keypair1.secret_key().as_bytes().len(),
        keypair2.secret_key().as_bytes().len()
    );
    Ok(())
}

/// Test error propagation
#[test]
fn test_error_propagation() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let invalid_secret_key = SigSecretKey::new(vec![0u8; 1000]);
    let result = fn_dsa.sign(&invalid_secret_key, b"test");
    assert!(
        result.is_err(),
        "Signing should fail with invalid secret key size"
    );

    let invalid_public_key = SigPublicKey::new(vec![0u8; 1000]);
    let signature = fn_dsa.sign(&keypair.secret_key, b"test")?;
    let result = fn_dsa.verify(&invalid_public_key, b"test", &signature);
    assert!(
        result.is_err(),
        "Verification should fail with invalid public key size"
    );
    Ok(())
}

/// Test performance characteristics
#[test]
fn test_performance_characteristics() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;
    let message = b"Performance test message";

    let start = std::time::Instant::now();
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    let sign_duration = start.elapsed();

    let start = std::time::Instant::now();
    let is_valid = fn_dsa.verify(&keypair.public_key, message, &signature)?;
    let verify_duration = start.elapsed();

    assert!(is_valid, "Signature should be valid");

    assert!(
        sign_duration.as_millis() < 1000,
        "Signing should complete within 1 second"
    );
    assert!(
        verify_duration.as_millis() < 1000,
        "Verification should complete within 1 second"
    );

    Ok(())
}

/// Test memory usage
#[test]
fn test_memory_usage() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

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

    let message = b"Memory test message";
    let signature = fn_dsa.sign(&keypair.secret_key, message)?;
    let expected_signature_size = signature_size(FN_DSA_LOGN_512);

    assert_eq!(signature.len(), expected_signature_size);
    Ok(())
}

/// Test SigKeypair functionality
#[test]
fn test_sig_keypair_functionality() -> TestResult {
    let fn_dsa = FnDsa512::new();

    let keypair = fn_dsa.generate_keypair()?;

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

    let message = b"Test message for keypair functionality";
    let signature = fn_dsa.sign(secret_key, message)?;
    let is_valid = fn_dsa.verify(public_key, message, &signature)?;
    assert!(is_valid, "Signature should be valid");

    let public_key_bytes = public_key.as_bytes().to_vec();
    let secret_key_bytes = secret_key.as_bytes().to_vec();
    let reconstructed_keypair = SigKeypair::new(public_key_bytes, secret_key_bytes);

    let signature2 = fn_dsa.sign(reconstructed_keypair.secret_key(), message)?;
    let is_valid2 = fn_dsa.verify(reconstructed_keypair.public_key(), message, &signature2)?;
    assert!(is_valid2, "Reconstructed keypair should work");

    assert!(
        is_valid && is_valid2,
        "Both keypairs should produce valid signatures"
    );
    Ok(())
}

/// Test SigKeypair with different security levels
#[test]
fn test_sig_keypair_security_levels() -> TestResult {
    let fn_dsa512 = FnDsa512::new();
    let keypair512 = fn_dsa512.generate_keypair()?;

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

    let fn_dsa1024 = FnDsa1024::new();
    let keypair1024 = fn_dsa1024.generate_keypair()?;

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

    assert!(
        keypair1024.public_key().as_bytes().len() > keypair512.public_key().as_bytes().len(),
        "1024-bit public key should be larger than 512-bit public key"
    );
    assert!(
        keypair1024.secret_key().as_bytes().len() > keypair512.secret_key().as_bytes().len(),
        "1024-bit secret key should be larger than 512-bit secret key"
    );

    let message = b"Test message for security level comparison";

    let signature512 = fn_dsa512.sign(keypair512.secret_key(), message)?;
    let is_valid512 = fn_dsa512.verify(keypair512.public_key(), message, &signature512)?;
    assert!(is_valid512, "512-bit signature should be valid");

    let signature1024 = fn_dsa1024.sign(keypair1024.secret_key(), message)?;
    let is_valid1024 = fn_dsa1024.verify(keypair1024.public_key(), message, &signature1024)?;
    assert!(is_valid1024, "1024-bit signature should be valid");
    Ok(())
}

/// Test edge cases
#[test]
fn test_edge_cases() -> TestResult {
    let fn_dsa = FnDsa512::new();
    let keypair = fn_dsa.generate_keypair()?;

    let empty_message = b"";
    let signature = fn_dsa.sign(&keypair.secret_key, empty_message)?;
    let is_valid = fn_dsa.verify(&keypair.public_key, empty_message, &signature)?;
    assert!(is_valid, "Empty message signature should be valid");

    let single_byte_message = b"a";
    let signature = fn_dsa.sign(&keypair.secret_key, single_byte_message)?;
    let is_valid = fn_dsa.verify(&keypair.public_key, single_byte_message, &signature)?;
    assert!(is_valid, "Single byte message signature should be valid");

    let null_message = b"Message with\0null bytes";
    let signature = fn_dsa.sign(&keypair.secret_key, null_message)?;
    let is_valid = fn_dsa.verify(&keypair.public_key, null_message, &signature)?;
    assert!(
        is_valid,
        "Message with null bytes signature should be valid"
    );
    Ok(())
}
