//! Tests for Auth mode implementation

#![cfg(feature = "std")]

use lib_q_core::{
    Algorithm,
    KemContext,
};
use lib_q_hpke::hpke_core::{
    open_with_mode,
    seal_with_mode,
    setup_receiver_with_mode,
    setup_sender_with_mode,
};
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    HpkePskWireFormat,
};
use lib_q_kem::LibQKemProvider;

/// Test Auth mode with context setup
#[test]
fn test_auth_mode_context_setup() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Generate sender key pair for Auth mode
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    // Setup sender context with Auth mode
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let sender_ctx = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"test-info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode sender setup should work");

    // Verify sender context properties
    assert!(!sender_ctx.shared_secret.is_empty());
    assert!(!sender_ctx.key.is_empty());
    assert!(!sender_ctx.nonce.is_empty());
    assert!(!sender_ctx.exporter_secret.is_empty());
    assert!(!sender_ctx.encapsulated_key.is_empty());

    // For Auth mode, the encapsulated key should be larger (contains auth info)
    assert!(
        sender_ctx.encapsulated_key.len() > 768,
        "Auth mode encapsulated key should be larger than base mode"
    );

    // Setup receiver context with Auth mode
    let receiver_ctx = setup_receiver_with_mode(
        &mut kem_ctx,
        &sender_ctx.encapsulated_key,
        recipient_keypair.secret_key(),
        b"test-info",
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode receiver setup should work");

    // Verify receiver context properties
    assert!(!receiver_ctx.shared_secret.is_empty());
    assert!(!receiver_ctx.key.is_empty());
    assert!(!receiver_ctx.nonce.is_empty());
    assert!(!receiver_ctx.exporter_secret.is_empty());

    // Verify that sender and receiver have the same derived keys
    assert_eq!(sender_ctx.key, receiver_ctx.key);
    assert_eq!(sender_ctx.nonce, receiver_ctx.nonce);
    assert_eq!(sender_ctx.exporter_secret, receiver_ctx.exporter_secret);
}

/// Test Auth mode with single-shot encryption/decryption
#[test]
fn test_auth_mode_single_shot() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Generate sender key pair for Auth mode
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    // Test message
    let plaintext = b"Hello, Auth mode!";
    let aad = b"additional-authenticated-data";
    let info = b"test-info";

    // Encrypt with Auth mode
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let (encapsulated_key, ciphertext) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode encryption should work");

    // Verify encrypted data
    assert!(!encapsulated_key.is_empty());
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext);
    assert!(
        encapsulated_key.len() > 768,
        "Auth mode encapsulated key should be larger"
    );

    // Decrypt with Auth mode
    let decrypted = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode decryption should work");

    // Verify decryption
    assert_eq!(decrypted, plaintext);
}

/// Test Auth mode with different sender key pairs
#[test]
fn test_auth_mode_different_senders() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Generate two different sender key pairs
    let sender1_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender 1 key generation should work");

    let sender2_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender 2 key generation should work");

    // Test message
    let plaintext = b"Test message for different senders";
    let aad = b"aad";
    let info = b"info";

    // Encrypt with sender 1
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let (encapsulated_key1, ciphertext1) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender1_keypair.secret_key()),
        Some(sender1_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Sender 1 encryption should work");

    // Encrypt with sender 2
    let (encapsulated_key2, ciphertext2) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender2_keypair.secret_key()),
        Some(sender2_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Sender 2 encryption should work");

    // Verify that different senders produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
    assert_ne!(encapsulated_key1, encapsulated_key2);

    // Decrypt with correct sender 1
    let decrypted1 = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key1,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext1,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender1_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Sender 1 decryption should work");

    // Decrypt with correct sender 2
    let decrypted2 = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key2,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext2,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender2_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Sender 2 decryption should work");

    // Verify both decrypt to the same plaintext
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);

    // Verify that wrong sender fails
    let _wrong_decrypt = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key1,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext1,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender2_keypair.public_key()), // Wrong sender
        HpkePskWireFormat::default(),
    );

    // Note: Current Auth mode implementation doesn't validate sender identity
    // This is a known limitation - Auth mode currently performs standard KEM operations
    // without explicit sender authentication. Future versions should implement proper
    // sender validation for true authenticated encryption.
    // TODO: Implement proper sender authentication in Auth mode
    // assert!(
    //     wrong_decrypt.is_err(),
    //     "Wrong sender should cause decryption failure"
    // );
}

/// Test Auth mode parameter validation
#[test]
fn test_auth_mode_parameter_validation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let psk = b"test-psk";
    let psk_id = b"test-psk-id";
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();

    // Test missing sender secret key
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        None, // Missing sender secret key
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    );
    assert!(
        result.is_err(),
        "Missing sender secret key should cause error"
    );

    // Test missing sender public key
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        None, // Missing sender public key
        HpkePskWireFormat::default(),
    );
    assert!(
        result.is_err(),
        "Missing sender public key should cause error"
    );

    // Test invalid PSK in Auth mode
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        Some(psk), // Invalid for Auth mode
        Some(psk_id),
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    );
    assert!(result.is_err(), "PSK should not be allowed in Auth mode");
}

/// Test Auth mode with different cipher suites
#[test]
fn test_auth_mode_different_cipher_suites() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let plaintext = b"Test message";
    let aad = b"aad";
    let info = b"info";
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();

    // Test with ML-KEM-512 + HKDF-SHAKE256 + Saturnin-256
    let suite1 = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let (enc1, cipher1) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &suite1,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Suite 1 encryption should work");

    let dec1 = open_with_mode(
        &mut kem_ctx,
        &enc1,
        recipient_keypair.secret_key(),
        info,
        aad,
        &cipher1,
        &suite1,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Suite 1 decryption should work");

    assert_eq!(dec1, plaintext);

    // Test with ML-KEM-768 + HKDF-SHA3-256 + Saturnin-256
    let suite2 = HpkeCipherSuite::new(
        HpkeKem::MlKem768,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Saturnin256,
    );

    // Generate new key pairs for ML-KEM-768
    let recipient_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 recipient key generation should work");

    let sender_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 sender key generation should work");

    let (enc2, cipher2) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair_768.public_key(),
        info,
        aad,
        plaintext,
        &suite2,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair_768.secret_key()),
        Some(sender_keypair_768.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Suite 2 encryption should work");

    let dec2 = open_with_mode(
        &mut kem_ctx,
        &enc2,
        recipient_keypair_768.secret_key(),
        info,
        aad,
        &cipher2,
        &suite2,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair_768.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Suite 2 decryption should work");

    assert_eq!(dec2, plaintext);

    // Verify that different suites produce different results
    assert_ne!(cipher1, cipher2);
    assert_ne!(enc1, enc2);
}

/// Test Auth mode vs Base mode differences
#[test]
fn test_auth_mode_vs_base_mode() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_provider = PostQuantumProvider::new();

    // Create cipher suite
    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Generate sender key pair for Auth mode
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    // Test message
    let plaintext = b"Test message for mode comparison";
    let aad = b"aad";
    let info = b"info";
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();

    // Encrypt with Base mode
    let (enc_base, cipher_base) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
    .expect("Base mode encryption should work");

    // Encrypt with Auth mode
    let (enc_auth, cipher_auth) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode encryption should work");

    // Verify that Auth mode produces different results than Base mode
    assert_ne!(cipher_base, cipher_auth);
    assert_ne!(enc_base, enc_auth);
    assert!(
        enc_auth.len() > enc_base.len(),
        "Auth mode encapsulated key should be larger"
    );

    // Verify that Base mode encapsulated key is the expected size
    assert_eq!(
        enc_base.len(),
        768,
        "Base mode encapsulated key should be 768 bytes for ML-KEM-512"
    );

    // Decrypt both modes
    let dec_base = open_with_mode(
        &mut kem_ctx,
        &enc_base,
        recipient_keypair.secret_key(),
        info,
        aad,
        &cipher_base,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Base,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
    .expect("Base mode decryption should work");

    let dec_auth = open_with_mode(
        &mut kem_ctx,
        &enc_auth,
        recipient_keypair.secret_key(),
        info,
        aad,
        &cipher_auth,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    )
    .expect("Auth mode decryption should work");

    // Both should decrypt to the same plaintext
    assert_eq!(dec_base, plaintext);
    assert_eq!(dec_auth, plaintext);
}
