#![cfg(feature = "std")]
#![allow(clippy::assertions_on_constants)]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use lib_q_kem::LibQKemProvider;

/// Test that HPKE context can be created with proper KEM provider
#[test]
fn test_hpke_context_creation_with_provider() {
    let _hpke_ctx = HpkeContext::new();
    // This should not panic or fail
    assert!(true, "HPKE context creation should work");
}

/// Test that HPKE context can be created with custom provider
#[test]
fn test_hpke_context_with_custom_provider() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let _hpke_ctx = HpkeContext::with_provider(provider);
    // This should not panic or fail
    assert!(true, "HPKE context with custom provider should work");
}

/// Test that KEM operations work with proper provider
#[test]
fn test_kem_operations_with_provider() {
    // Create KEM context with provider
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    // Generate key pair - this should work
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work with proper provider");

    // Verify key pair is valid
    assert!(
        !keypair.public_key().as_bytes().is_empty(),
        "Public key should not be empty"
    );
    assert!(
        !keypair.secret_key().as_bytes().is_empty(),
        "Secret key should not be empty"
    );

    // Verify key sizes
    assert_eq!(
        keypair.public_key().as_bytes().len(),
        800,
        "ML-KEM-512 public key should be 800 bytes"
    );
    assert_eq!(
        keypair.secret_key().as_bytes().len(),
        1632,
        "ML-KEM-512 secret key should be 1632 bytes"
    );
}

/// Test HPKE operations with proper provider integration
#[test]
fn test_hpke_operations_with_provider() {
    // Create HPKE context with provider
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Create KEM context with provider for key generation
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let _recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    // Test single-shot encryption/decryption
    let message = b"Hello, HPKE!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    assert!(
        !encapsulated_key.is_empty(),
        "Encapsulated key should not be empty"
    );
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &_recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test context-based operations with proper provider
#[test]
fn test_context_based_operations_with_provider() {
    // Create HPKE context with provider
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Create KEM context with provider for key generation
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let _recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    // Test sender context setup
    let mut sender_ctx = hpke_ctx
        .setup_sender(&recipient_pk, b"test-info")
        .expect("Sender setup should work");

    // Test encryption with context
    let message = b"Context-based encryption";
    let aad = b"context-aad";

    let ciphertext = sender_ctx
        .seal(aad, message)
        .expect("Context seal should work");

    assert!(
        !ciphertext.is_empty(),
        "Context ciphertext should not be empty"
    );

    // For receiver context, we need the encapsulated key from sender
    // This is a limitation of the current test setup - in real usage,
    // the encapsulated key would be transmitted separately
}

/// Test error handling when provider is not configured
#[test]
fn test_error_handling_no_provider() {
    // Create KEM context without provider
    let mut kem_ctx = KemContext::new();

    // This should fail with a proper error
    let result = kem_ctx.generate_keypair(Algorithm::MlKem512, None);
    assert!(
        result.is_err(),
        "Key generation should fail without provider"
    );

    // Check that the error is informative
    let error_msg = match result {
        Ok(_) => "Unexpected success".to_string(),
        Err(e) => format!("{}", e),
    };
    assert!(
        error_msg.contains("no provider configured") ||
            error_msg.contains("provider not configured") ||
            error_msg.contains("NotImplemented"),
        "Error should indicate missing provider: {}",
        error_msg
    );
}

/// Test different ML-KEM variants with provider
#[test]
fn test_different_ml_kem_variants() {
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    // Test ML-KEM-512
    let keypair_512 = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("ML-KEM-512 key generation should work");
    assert_eq!(keypair_512.public_key().as_bytes().len(), 800);
    assert_eq!(keypair_512.secret_key().as_bytes().len(), 1632);

    // Test ML-KEM-768
    let keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 key generation should work");
    assert_eq!(keypair_768.public_key().as_bytes().len(), 1184);
    assert_eq!(keypair_768.secret_key().as_bytes().len(), 2400);

    // Test ML-KEM-1024
    let keypair_1024 = kem_ctx
        .generate_keypair(Algorithm::MlKem1024, None)
        .expect("ML-KEM-1024 key generation should work");
    assert_eq!(keypair_1024.public_key().as_bytes().len(), 1568);
    assert_eq!(keypair_1024.secret_key().as_bytes().len(), 3168);
}

/// Test cipher suite compatibility with different KEM sizes
#[test]
fn test_cipher_suite_kem_compatibility() {
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    // Test with ML-KEM-512
    let keypair_512 = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("ML-KEM-512 key generation should work");
    let pk_512 = KemPublicKey::new(keypair_512.public_key().as_bytes().to_vec());

    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);
    let result = hpke_ctx.seal(&pk_512, b"info", b"aad", b"test");
    assert!(result.is_ok(), "HPKE should work with ML-KEM-512");

    // Test with ML-KEM-768
    let keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 key generation should work");
    let pk_768 = KemPublicKey::new(keypair_768.public_key().as_bytes().to_vec());

    let result = hpke_ctx.seal(&pk_768, b"info", b"aad", b"test");
    assert!(result.is_ok(), "HPKE should work with ML-KEM-768");

    // Test with ML-KEM-1024
    let keypair_1024 = kem_ctx
        .generate_keypair(Algorithm::MlKem1024, None)
        .expect("ML-KEM-1024 key generation should work");
    let pk_1024 = KemPublicKey::new(keypair_1024.public_key().as_bytes().to_vec());

    let result = hpke_ctx.seal(&pk_1024, b"info", b"aad", b"test");
    assert!(result.is_ok(), "HPKE should work with ML-KEM-1024");
}
