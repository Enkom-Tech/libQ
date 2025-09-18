//! Tests for PSK mode implementation

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
};
use lib_q_kem::LibQKemProvider;

/// Test PSK mode with context setup
#[test]
fn test_psk_mode_context_setup() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
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

    // Create PSK and PSK ID
    let psk = b"test-psk-key-material";
    let psk_id = b"test-psk-identifier";

    // Setup sender context with PSK mode
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();
    let sender_ctx = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"test-info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
    )
    .expect("PSK mode sender setup should work");

    // Verify sender context properties
    assert!(!sender_ctx.shared_secret.is_empty());
    assert!(!sender_ctx.key.is_empty());
    assert!(!sender_ctx.nonce.is_empty());
    assert!(!sender_ctx.exporter_secret.is_empty());
    assert!(!sender_ctx.encapsulated_key.is_empty());

    // Setup receiver context with PSK mode
    let receiver_ctx = setup_receiver_with_mode(
        &mut kem_ctx,
        &sender_ctx.encapsulated_key,
        recipient_keypair.secret_key(),
        b"test-info",
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
    )
    .expect("PSK mode receiver setup should work");

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

/// Test PSK mode with single-shot encryption/decryption
#[test]
fn test_psk_mode_single_shot() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
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

    // Create PSK and PSK ID
    let psk = b"test-psk-key-material";
    let psk_id = b"test-psk-identifier";

    // Test message
    let plaintext = b"Hello, PSK mode!";
    let aad = b"additional-authenticated-data";
    let info = b"test-info";

    // Encrypt with PSK mode
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
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
    )
    .expect("PSK mode encryption should work");

    // Verify encrypted data
    assert!(!encapsulated_key.is_empty());
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext);

    // Decrypt with PSK mode
    let decrypted = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
    )
    .expect("PSK mode decryption should work");

    // Verify decryption
    assert_eq!(decrypted, plaintext);
}

/// Test PSK mode with different PSK values
#[test]
fn test_psk_mode_different_psks() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
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

    // Test message
    let plaintext = b"Test message for different PSKs";
    let aad = b"aad";
    let info = b"info";

    // PSK 1
    let psk1 = b"first-psk";
    let psk_id1 = b"first-psk-id";

    // PSK 2
    let psk2 = b"second-psk";
    let psk_id2 = b"second-psk-id";

    // Encrypt with PSK 1
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
        HpkeMode::Psk,
        Some(psk1),
        Some(psk_id1),
        None,
        None,
    )
    .expect("PSK 1 encryption should work");

    // Encrypt with PSK 2
    let (encapsulated_key2, ciphertext2) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk2),
        Some(psk_id2),
        None,
        None,
    )
    .expect("PSK 2 encryption should work");

    // Verify that different PSKs produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
    assert_ne!(encapsulated_key1, encapsulated_key2);

    // Decrypt with correct PSK 1
    let decrypted1 = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key1,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext1,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Psk,
        Some(psk1),
        Some(psk_id1),
        None,
    )
    .expect("PSK 1 decryption should work");

    // Decrypt with correct PSK 2
    let decrypted2 = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key2,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext2,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Psk,
        Some(psk2),
        Some(psk_id2),
        None,
    )
    .expect("PSK 2 decryption should work");

    // Verify both decrypt to the same plaintext
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);

    // Verify that wrong PSK fails
    let wrong_decrypt = open_with_mode(
        &mut kem_ctx,
        &encapsulated_key1,
        recipient_keypair.secret_key(),
        info,
        aad,
        &ciphertext1,
        &cipher_suite,
        &hpke_provider,
        HpkeMode::Psk,
        Some(psk2), // Wrong PSK
        Some(psk_id1),
        None,
    );

    assert!(
        wrong_decrypt.is_err(),
        "Wrong PSK should cause decryption failure"
    );
}

/// Test PSK mode parameter validation
#[test]
fn test_psk_mode_parameter_validation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
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

    let psk = b"test-psk";
    let psk_id = b"test-psk-id";
    let mut rng = lib_q_hpke::security::prng::SimpleRng::new();

    // Test missing PSK
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        None, // Missing PSK
        Some(psk_id),
        None,
        None,
    );
    assert!(result.is_err(), "Missing PSK should cause error");

    // Test missing PSK ID
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk),
        None, // Missing PSK ID
        None,
        None,
    );
    assert!(result.is_err(), "Missing PSK ID should cause error");

    // Test invalid sender keys in PSK mode
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        Some(sender_keypair.secret_key()), // Invalid for PSK mode
        Some(sender_keypair.public_key()),
    );
    assert!(
        result.is_err(),
        "Sender keys should not be allowed in PSK mode"
    );
}

/// Test PSK mode with different cipher suites
#[test]
fn test_psk_mode_different_cipher_suites() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(Box::new(
        LibQKemProvider::new().expect("Failed to create KEM provider"),
    ));
    let hpke_provider = PostQuantumProvider::new();

    // Generate recipient key pair
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let psk = b"test-psk";
    let psk_id = b"test-psk-id";
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
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
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
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
    )
    .expect("Suite 1 decryption should work");

    assert_eq!(dec1, plaintext);

    // Test with ML-KEM-768 + HKDF-SHA3-256 + Saturnin-256
    let suite2 = HpkeCipherSuite::new(
        HpkeKem::MlKem768,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Saturnin256,
    );

    // Generate new key pair for ML-KEM-768
    let recipient_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 key generation should work");

    let (enc2, cipher2) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair_768.public_key(),
        info,
        aad,
        plaintext,
        &suite2,
        &hpke_provider,
        &mut rng,
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
        None,
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
        HpkeMode::Psk,
        Some(psk),
        Some(psk_id),
        None,
    )
    .expect("Suite 2 decryption should work");

    assert_eq!(dec2, plaintext);

    // Verify that different suites produce different results
    assert_ne!(cipher1, cipher2);
    assert_ne!(enc1, enc2);
}
