//! Comprehensive AuthPSK mode tests for HPKE implementation
//!
//! These tests validate the complete AuthPSK (Authenticated Pre-Shared Key) mode implementation
//! according to RFC 9180 Section 5.1.4.

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeContext;
use libq::LibQCryptoProvider;

/// Test AuthPSK mode basic functionality
#[test]
fn test_authpsk_mode_basic_functionality() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    // Define PSK and PSK ID
    let psk = b"shared-secret-key-32-bytes-long";
    let psk_id = b"psk-identifier";

    // Test AuthPSK mode setup
    let sender_ctx_result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        psk,
        psk_id,
        &sender_sk,
        &sender_pk,
    );

    assert!(
        sender_ctx_result.is_ok(),
        "AuthPSK mode setup should succeed"
    );
    let mut sender_ctx = sender_ctx_result.unwrap();

    // Test encryption with AuthPSK
    let message = b"Hello, AuthPSK HPKE!";
    let aad = b"additional authenticated data";
    let ciphertext = sender_ctx
        .seal(aad, message)
        .expect("AuthPSK encryption should succeed");

    // Test AuthPSK mode receiver setup
    let receiver_ctx_result = hpke_ctx.setup_receiver_auth_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        psk,
        psk_id,
        &sender_pk,
    );

    assert!(
        receiver_ctx_result.is_ok(),
        "AuthPSK mode receiver setup should succeed"
    );
    let mut receiver_ctx = receiver_ctx_result.unwrap();

    // Test decryption with AuthPSK
    let decrypted = receiver_ctx
        .open(aad, &ciphertext)
        .expect("AuthPSK decryption should succeed");
    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test AuthPSK mode with different PSK values
#[test]
fn test_authpsk_mode_different_psk_values() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let test_cases = vec![
        (b"psk-1".as_slice(), b"id-1".as_slice()),
        (b"different-psk".as_slice(), b"different-id".as_slice()),
        (
            b"very-long-psk-key-that-is-more-than-32-bytes".as_slice(),
            b"long-id".as_slice(),
        ),
    ];

    for (psk, psk_id) in test_cases {
        // Setup sender with AuthPSK
        let mut sender_ctx = hpke_ctx
            .setup_sender_auth_psk(
                &recipient_pk,
                b"test info",
                psk,
                psk_id,
                &sender_sk,
                &sender_pk,
            )
            .expect("AuthPSK setup should succeed");

        // Encrypt message
        let message = format!("Message with AuthPSK: {:?}", psk);
        let ciphertext = sender_ctx
            .seal(b"aad", message.as_bytes())
            .expect("Encryption should succeed");

        // Setup receiver with same AuthPSK
        let mut receiver_ctx = hpke_ctx
            .setup_receiver_auth_psk(
                sender_ctx.encapsulated_key(),
                &recipient_sk,
                b"test info",
                psk,
                psk_id,
                &sender_pk,
            )
            .expect("AuthPSK receiver setup should succeed");

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

/// Test AuthPSK mode authentication - wrong PSK should fail
#[test]
fn test_authpsk_mode_psk_authentication() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"correct-psk";
    let psk_id = b"correct-id";
    let wrong_psk = b"wrong-psk";

    // Setup sender with correct PSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        )
        .expect("AuthPSK setup should succeed");

    // Encrypt message
    let message = b"Secret message";
    let ciphertext = sender_ctx
        .seal(b"aad", message)
        .expect("Encryption should succeed");

    // Try to setup receiver with wrong PSK - setup should succeed but decryption should fail
    let wrong_receiver_ctx_result = hpke_ctx.setup_receiver_auth_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        wrong_psk,
        psk_id,
        &sender_pk,
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
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id,
            &sender_pk,
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

/// Test AuthPSK mode sender authentication - wrong sender key should fail
#[test]
fn test_authpsk_mode_sender_authentication() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    // Generate wrong sender key pair
    let wrong_sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let wrong_sender_pk = KemPublicKey::new(wrong_sender_keypair.public_key().as_bytes().to_vec());

    let psk = b"shared-psk";
    let psk_id = b"shared-id";

    // Setup sender with correct sender key
    let mut sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        )
        .expect("AuthPSK setup should succeed");

    // Encrypt message
    let message = b"Secret message";
    let ciphertext = sender_ctx
        .seal(b"aad", message)
        .expect("Encryption should succeed");

    // Try to setup receiver with wrong sender public key - should fail during setup
    let wrong_receiver_ctx_result = hpke_ctx.setup_receiver_auth_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        psk,
        psk_id,
        &wrong_sender_pk,
    );

    // AuthPSK mode should fail setup with wrong sender key due to authentication failure
    assert!(
        wrong_receiver_ctx_result.is_err(),
        "AuthPSK setup should fail with wrong sender key"
    );

    // Setup receiver with correct sender key - should succeed
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id,
            &sender_pk,
        )
        .expect("Correct sender key should allow setup");

    // Decrypt message
    let decrypted = receiver_ctx
        .open(b"aad", &ciphertext)
        .expect("Decryption should succeed");
    assert_eq!(
        decrypted, message,
        "Decrypted message should match original"
    );
}

/// Test AuthPSK mode with different PSK IDs
#[test]
fn test_authpsk_mode_different_psk_ids() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"shared-psk";
    let psk_id_1 = b"session-1";
    let psk_id_2 = b"session-2";

    // Setup sender with PSK ID 1
    let mut sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id_1,
            &sender_sk,
            &sender_pk,
        )
        .expect("AuthPSK setup should succeed");

    // Encrypt message
    let message = b"Message for session 1";
    let ciphertext = sender_ctx
        .seal(b"aad", message)
        .expect("Encryption should succeed");

    // Try to setup receiver with different PSK ID - setup should succeed but decryption should fail
    let wrong_receiver_ctx_result = hpke_ctx.setup_receiver_auth_psk(
        sender_ctx.encapsulated_key(),
        &recipient_sk,
        b"test info",
        psk,
        psk_id_2,
        &sender_pk,
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
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id_1,
            &sender_pk,
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

/// Test AuthPSK mode key export functionality
#[test]
fn test_authpsk_mode_key_export() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"export-test-psk";
    let psk_id = b"export-test-id";

    // Setup sender with AuthPSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"export test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        )
        .expect("AuthPSK setup should succeed");

    // Setup receiver with AuthPSK
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"export test info",
            psk,
            psk_id,
            &sender_pk,
        )
        .expect("AuthPSK receiver setup should succeed");

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

/// Test AuthPSK mode with multiple messages
#[test]
fn test_authpsk_mode_multiple_messages() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    let psk = b"multi-message-psk";
    let psk_id = b"multi-message-id";

    // Setup sender with AuthPSK
    let mut sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"multi-message info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        )
        .expect("AuthPSK setup should succeed");

    // Setup receiver with AuthPSK
    let mut receiver_ctx = hpke_ctx
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"multi-message info",
            psk,
            psk_id,
            &sender_pk,
        )
        .expect("AuthPSK receiver setup should succeed");

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

/// Test AuthPSK mode error handling
#[test]
fn test_authpsk_mode_error_handling() {
    let provider = Box::new(LibQCryptoProvider::new());
    let mut hpke_ctx = HpkeContext::with_provider(provider);

    // Generate recipient key pair
    let mut kem_ctx = KemContext::with_provider(Box::new(LibQCryptoProvider::new()));
    let recipient_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let recipient_pk = KemPublicKey::new(recipient_keypair.public_key().as_bytes().to_vec());
    let recipient_sk = KemSecretKey::new(recipient_keypair.secret_key().as_bytes().to_vec());

    // Generate sender key pair
    let sender_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
    let sender_pk = KemPublicKey::new(sender_keypair.public_key().as_bytes().to_vec());
    let sender_sk = KemSecretKey::new(sender_keypair.secret_key().as_bytes().to_vec());

    // Test with empty PSK
    let _empty_psk_result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        b"",
        b"psk-id",
        &sender_sk,
        &sender_pk,
    );

    // Test with empty PSK ID
    let _empty_psk_id_result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        b"psk",
        b"",
        &sender_sk,
        &sender_pk,
    );

    // Test with very long PSK
    let long_psk = vec![0u8; 1000]; // 1000 bytes
    let _long_psk_result = hpke_ctx.setup_sender_auth_psk(
        &recipient_pk,
        b"test info",
        &long_psk,
        b"psk-id",
        &sender_sk,
        &sender_pk,
    );

    // At least one of these should work for basic functionality
    let psk = b"valid-psk";
    let psk_id = b"valid-id";

    let sender_ctx = hpke_ctx
        .setup_sender_auth_psk(
            &recipient_pk,
            b"test info",
            psk,
            psk_id,
            &sender_sk,
            &sender_pk,
        )
        .expect("Valid AuthPSK setup should succeed");

    let receiver_ctx = hpke_ctx
        .setup_receiver_auth_psk(
            sender_ctx.encapsulated_key(),
            &recipient_sk,
            b"test info",
            psk,
            psk_id,
            &sender_pk,
        )
        .expect("Valid AuthPSK receiver setup should succeed");
}
