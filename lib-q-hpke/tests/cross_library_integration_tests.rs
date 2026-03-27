//! Cross-library integration tests for HPKE with different KEM providers
//!
//! These tests verify that HPKE works correctly with different KEM implementations
//! (ML-KEM, HQC, CB-KEM, DAWN) to ensure proper cross-library interoperability.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use lib_q_kem::LibQKemProvider;

/// Test HPKE with ML-KEM-512
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_with_ml_kem512() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE with ML-KEM-512!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test HPKE with ML-KEM-768
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_with_ml_kem768() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE with ML-KEM-768!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test HPKE with HQC-128
#[test]
#[cfg(all(feature = "ml-kem", feature = "hqc"))]
fn test_hpke_with_hqc128() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::Hqc128, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE with HQC-128!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test HPKE with HQC-192
#[test]
#[cfg(all(feature = "ml-kem", feature = "hqc"))]
fn test_hpke_with_hqc192() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::Hqc192, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE with HQC-192!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test HPKE with HQC-256
#[test]
#[cfg(all(feature = "ml-kem", feature = "hqc"))]
fn test_hpke_with_hqc256() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::Hqc256, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE with HQC-256!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    let decrypted = hpke_ctx
        .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
        .expect("Open operation should work");

    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test error propagation from KEM operations to HPKE
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_error_propagation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Create an invalid public key (wrong size)
    let invalid_pk = KemPublicKey::new(vec![0u8; 100]);
    let message = b"test message";
    let info = b"test-info";
    let aad = b"test-aad";

    // This should fail with an appropriate error
    let result = hpke_ctx.seal(&invalid_pk, info, aad, message);
    assert!(result.is_err(), "Seal should fail with invalid public key");
}

/// Test HPKE with multiple KEM algorithms in sequence
#[test]
#[cfg(all(feature = "ml-kem", feature = "hqc"))]
fn test_hpke_multiple_kem_algorithms() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let algorithms = [Algorithm::MlKem512, Algorithm::Hqc128, Algorithm::Hqc192];

    for algorithm in algorithms {
        let keypair = kem_ctx
            .generate_keypair(algorithm, None)
            .unwrap_or_else(|e| {
                panic!("Key generation should work for {algorithm:?}: {e}");
            });

        let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
        let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

        let message = format!("Hello, HPKE with {:?}!", algorithm).into_bytes();
        let info = b"test-info";
        let aad = b"test-aad";

        let (encapsulated_key, ciphertext) = hpke_ctx
            .seal(&recipient_pk, info, aad, &message)
            .unwrap_or_else(|e| panic!("Seal should work for {algorithm:?}: {e}"));

        let decrypted = hpke_ctx
            .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
            .unwrap_or_else(|e| panic!("Open should work for {algorithm:?}: {e}"));

        assert_eq!(
            decrypted, message,
            "Decrypted message should match original for {:?}",
            algorithm
        );
    }
}

/// Test HPKE with different message sizes
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_different_message_sizes() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let info = b"test-info";
    let aad = b"test-aad";

    // Test with different message sizes
    let messages = [
        b"".as_slice(),              // Empty message
        b"a".as_slice(),             // Single byte
        b"Hello, World!".as_slice(), // Short message
        &vec![0u8; 1024],            // 1KB message
        &vec![0u8; 10 * 1024],       // 10KB message
    ];

    for message in messages {
        let (encapsulated_key, ciphertext) = hpke_ctx
            .seal(&recipient_pk, info, aad, message)
            .expect("Seal should work for all message sizes");

        let decrypted = hpke_ctx
            .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
            .expect("Open should work for all message sizes");

        assert_eq!(
            decrypted,
            message,
            "Decrypted message should match original for size {}",
            message.len()
        );
    }
}

/// Test HPKE with different AAD sizes
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_different_aad_sizes() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE!";
    let info = b"test-info";

    // Test with different AAD sizes
    let aads = [
        b"".as_slice(),         // Empty AAD
        b"a".as_slice(),        // Single byte
        b"test-aad".as_slice(), // Short AAD
        &vec![0u8; 256],        // 256 bytes
    ];

    for aad in aads {
        let (encapsulated_key, ciphertext) = hpke_ctx
            .seal(&recipient_pk, info, aad, message)
            .expect("Seal should work for all AAD sizes");

        let decrypted = hpke_ctx
            .open(&encapsulated_key, &recipient_sk, info, aad, &ciphertext)
            .expect("Open should work for all AAD sizes");

        assert_eq!(
            decrypted,
            message,
            "Decrypted message should match original for AAD size {}",
            aad.len()
        );
    }
}

/// Test that HPKE fails with mismatched keys
#[test]
#[cfg(feature = "ml-kem")]
fn test_hpke_mismatched_keys() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));

    // Generate two different keypairs
    let keypair1 = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let keypair2 = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let recipient_pk = KemPublicKey::new(keypair1.public_key().as_bytes().to_vec());
    let wrong_sk = KemSecretKey::new(keypair2.secret_key().as_bytes().to_vec());

    let message = b"Hello, HPKE!";
    let info = b"test-info";
    let aad = b"test-aad";

    let (encapsulated_key, ciphertext) = hpke_ctx
        .seal(&recipient_pk, info, aad, message)
        .expect("Seal operation should work");

    // Try to decrypt with wrong secret key - should fail
    let result = hpke_ctx.open(&encapsulated_key, &wrong_sk, info, aad, &ciphertext);
    assert!(result.is_err(), "Open should fail with mismatched keys");
}
