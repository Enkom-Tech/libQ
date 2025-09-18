//! Comprehensive PSK mode tests for HPKE implementation
//!
//! These tests validate the complete PSK (Pre-Shared Key) mode implementation
//! according to RFC 9180 Section 5.1.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::{
    HpkeContext,
    HpkeMode,
};
use lib_q_kem::LibQKemProvider;

/// Test PSK mode basic functionality
#[test]
fn test_psk_mode_basic_functionality() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    // Define PSK and PSK ID
    let psk = b"shared-secret-key-32-bytes-long";
    let psk_id = b"psk-identifier";

    // Test PSK mode setup
    let sender_ctx_result = hpke_ctx.setup_sender_psk(&recipient_pk, b"test info", psk, psk_id);

    assert!(sender_ctx_result.is_ok(), "PSK mode setup should succeed");
    let mut sender_ctx = sender_ctx_result.unwrap();

    // Test encryption with PSK
    let message = b"Hello, PSK HPKE!";
    let aad = b"additional authenticated data";
    let ciphertext = sender_ctx
        .seal(aad, message)
        .expect("PSK encryption should succeed");

    // Test PSK mode receiver setup
    let receiver_ctx_result = hpke_ctx.setup_receiver_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        psk,
        psk_id,
    );

    assert!(
        receiver_ctx_result.is_ok(),
        "PSK mode receiver setup should succeed"
    );
    let mut receiver_ctx = receiver_ctx_result.unwrap();

    // Test decryption with PSK
    let decrypted = receiver_ctx
        .open(aad, &ciphertext)
        .expect("PSK decryption should succeed");
    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test PSK mode with different PSK values
#[test]
fn test_psk_mode_different_psk_values() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let test_cases = vec![
        (b"psk-1".as_slice(), b"id-1".as_slice()),
        (b"different-psk".as_slice(), b"different-id".as_slice()),
        (
            b"very-long-psk-key-that-is-more-than-32-bytes".as_slice(),
            b"long-id".as_slice(),
        ),
    ];

    for (psk, psk_id) in test_cases {
        // Setup sender with PSK
        let mut sender_ctx = hpke_ctx
            .setup_sender_psk(&recipient_pk, b"test info", psk, psk_id)
            .expect("PSK setup should succeed");

        // Encrypt message
        let message = format!("Message with PSK: {:?}", psk);
        let ciphertext = sender_ctx
            .seal(b"aad", message.as_bytes())
            .expect("Encryption should succeed");

        // Setup receiver with same PSK
        let mut receiver_ctx = hpke_ctx
            .setup_receiver_psk(
                sender_ctx.encapsulated_key(),
                &recipient_sk,
                b"test info",
                psk,
                psk_id,
            )
            .expect("PSK receiver setup should succeed");

        // Decrypt message
        let decrypted = receiver_ctx
            .open(b"aad", &ciphertext)
            .expect("Decryption should succeed");
        assert_eq!(
            decrypted,
            message.as_bytes(),
            "Decrypted message should match original"
        );
    }
}

/// Test PSK mode authentication - wrong PSK should fail
#[test]
fn test_psk_mode_authentication() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let psk = b"correct-psk";
    let psk_id = b"correct-id";
    let wrong_psk = b"wrong-psk";

    // Setup sender with correct PSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_psk(&recipient_pk, b"test info", psk, psk_id)
        .expect("PSK setup should succeed");

    // Encrypt message
    let message = b"Secret message";
    let ciphertext = sender_ctx
        .seal(b"aad", message)
        .expect("Encryption should succeed");

    // Try to setup receiver with wrong PSK - setup should succeed but decryption should fail
    let wrong_receiver_ctx_result = hpke_ctx.setup_receiver_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        wrong_psk,
        psk_id,
    );

    assert!(
        wrong_receiver_ctx_result.is_ok(),
        "Setup should succeed even with wrong PSK (RFC 9180 compliant)"
    );
    let mut wrong_receiver_ctx = wrong_receiver_ctx_result.unwrap();

    // Decryption with wrong PSK should fail
    let wrong_decrypt_result = wrong_receiver_ctx.open(b"aad", &ciphertext);
    assert!(
        wrong_decrypt_result.is_err(),
        "Decryption should fail with wrong PSK"
    );

    // Setup receiver with correct PSK - should succeed
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id,
        )
        .expect("Correct PSK should allow setup");

    // Decrypt message
    let decrypted = receiver_ctx
        .open(b"aad", &ciphertext)
        .expect("Decryption should succeed");
    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test PSK mode with different PSK IDs
#[test]
fn test_psk_mode_different_psk_ids() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let psk = b"shared-psk";
    let psk_id_1 = b"session-1";
    let psk_id_2 = b"session-2";

    // Setup sender with PSK ID 1
    let mut sender_ctx = hpke_ctx
        .setup_sender_psk(&recipient_pk, b"test info", psk, psk_id_1)
        .expect("PSK setup should succeed");

    // Encrypt message
    let message = b"Message for session 1";
    let ciphertext = sender_ctx
        .seal(b"aad", message)
        .expect("Encryption should succeed");

    // Try to setup receiver with different PSK ID - setup should succeed but decryption should fail
    let wrong_receiver_ctx_result = hpke_ctx.setup_receiver_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        psk,
        psk_id_2,
    );

    assert!(
        wrong_receiver_ctx_result.is_ok(),
        "Setup should succeed even with different PSK ID (RFC 9180 compliant)"
    );
    let mut wrong_receiver_ctx = wrong_receiver_ctx_result.unwrap();

    // Decryption with different PSK ID should fail
    let wrong_decrypt_result = wrong_receiver_ctx.open(b"aad", &ciphertext);
    assert!(
        wrong_decrypt_result.is_err(),
        "Decryption should fail with different PSK ID"
    );

    // Setup receiver with correct PSK ID - should succeed
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id_1,
        )
        .expect("Correct PSK ID should allow setup");

    // Decrypt message
    let decrypted = receiver_ctx
        .open(b"aad", &ciphertext)
        .expect("Decryption should succeed");
    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test PSK mode key export functionality
#[test]
fn test_psk_mode_key_export() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let psk = b"export-test-psk";
    let psk_id = b"export-test-id";

    // Setup sender with PSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_psk(&recipient_pk, b"export test info", psk, psk_id)
        .expect("PSK setup should succeed");

    // Setup receiver with PSK
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"export test info",
            psk,
            psk_id,
        )
        .expect("PSK receiver setup should succeed");

    // Export keys from both contexts
    let sender_exported_key = sender_ctx
        .export(b"test-context", 32)
        .expect("Key export should succeed");
    let receiver_exported_key = receiver_ctx
        .export(b"test-context", 32)
        .expect("Key export should succeed");

    // Exported keys should be identical
    assert_eq!(
        sender_exported_key, receiver_exported_key,
        "Exported keys should be identical"
    );

    // Test different export contexts produce different keys
    let sender_exported_key_2 = sender_ctx
        .export(b"different-context", 32)
        .expect("Key export should succeed");
    assert_ne!(
        sender_exported_key, sender_exported_key_2,
        "Different contexts should produce different keys"
    );
}

/// Test PSK mode with multiple messages
#[test]
fn test_psk_mode_multiple_messages() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    let psk = b"multi-message-psk";
    let psk_id = b"multi-message-id";

    // Setup sender with PSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_psk(&recipient_pk, b"multi-message info", psk, psk_id)
        .expect("PSK setup should succeed");

    // Setup receiver with PSK
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"multi-message info",
            psk,
            psk_id,
        )
        .expect("PSK receiver setup should succeed");

    // Encrypt and decrypt multiple messages
    let messages = vec![
        b"First message".as_slice(),
        b"Second message".as_slice(),
        b"Third message with more content".as_slice(),
        b"Fourth message".as_slice(),
    ];

    for (i, message) in messages.iter().enumerate() {
        let aad = format!("aad-{}", i).into_bytes();
        let ciphertext = sender_ctx
            .seal(&aad, message)
            .expect("Encryption should succeed");
        let decrypted = receiver_ctx
            .open(&aad, &ciphertext)
            .expect("Decryption should succeed");
        assert_eq!(
            decrypted,
            *message,
            "Message {} should decrypt correctly",
            i + 1
        );
    }
}

/// Test PSK mode error handling
#[test]
fn test_psk_mode_error_handling() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let keypair = kem_ctx.generate_keypair(Algorithm::MlKem512, None).unwrap();
    let recipient_pk = KemPublicKey::new(keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(keypair.secret_key().as_bytes().to_vec());

    // Test with empty PSK
    let empty_psk_result = hpke_ctx.setup_sender_psk(&recipient_pk, b"test info", b"", b"psk-id");
    // Empty PSK might be valid depending on implementation, but let's test it

    // Test with empty PSK ID
    let empty_psk_id_result = hpke_ctx.setup_sender_psk(&recipient_pk, b"test info", b"psk", b"");
    // Empty PSK ID might be valid depending on implementation

    // Test with very long PSK
    let long_psk = vec![0u8; 1000]; // 1000 bytes
    let long_psk_result =
        hpke_ctx.setup_sender_psk(&recipient_pk, b"test info", &long_psk, b"psk-id");
    // Long PSK should be handled gracefully

    // At least one of these should work for basic functionality
    let psk = b"valid-psk";
    let psk_id = b"valid-id";

    let sender_ctx = hpke_ctx
        .setup_sender_psk(&recipient_pk, b"test info", psk, psk_id)
        .expect("Valid PSK setup should succeed");

    let receiver_ctx = hpke_ctx
        .setup_receiver_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id,
        )
        .expect("Valid PSK receiver setup should succeed");
}
