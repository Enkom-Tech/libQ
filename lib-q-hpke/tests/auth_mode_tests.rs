//! Tests for Auth mode implementation
//!
//! B14 interim fix: HPKE Auth mode does not currently bind the sender's static secret key into
//! the authentication tag or shared secret (RFC 9180 Section 5.1.3 AuthEncap/AuthDecap gap), so it
//! is disabled and fails closed. These tests used to assert that full Auth-mode round trips
//! succeeded (context setup, single-shot seal/open, different senders, different cipher suites,
//! Auth vs Base mode); they now assert the fail-closed behavior instead. See
//! `lib-q-hpke/tests/auth_encap_validation_tests.rs` for the forgery this replaced and
//! `PostQuantumProvider::auth_mode_unavailable` for the rationale.

#![cfg(feature = "std")]

use std::sync::Arc;

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
use lib_q_hpke::providers::traits::HpkeCryptoProvider;
use lib_q_hpke::types::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
    HpkeMode,
    HpkePskWireFormat,
};
use lib_q_kem::LibQKemProvider;

/// Test Auth mode context setup fails closed (B14)
#[test]
fn test_auth_mode_context_setup_fails_closed() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();
    let sender_result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"test-info",
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    );
    assert!(
        sender_result.is_err(),
        "Auth mode sender setup must fail closed (B14)"
    );

    // With no valid sender context to build a real encapsulated key from, exercise receiver setup
    // against a well-formed-sized placeholder — it must fail closed too.
    let placeholder_enc = vec![0u8; HpkeKem::MlKem512.enc_len() * 2 + 32];
    let receiver_result = setup_receiver_with_mode(
        &mut kem_ctx,
        &placeholder_enc,
        recipient_keypair.secret_key(),
        b"test-info",
        &cipher_suite,
        hpke_crypto.as_ref(),
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    );
    assert!(
        receiver_result.is_err(),
        "Auth mode receiver setup must fail closed (B14)"
    );
}

/// Test Auth mode single-shot encryption fails closed (B14)
#[test]
fn test_auth_mode_single_shot_fails_closed() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let plaintext = b"Hello, Auth mode!";
    let aad = b"additional-authenticated-data";
    let info = b"test-info";

    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();
    let result = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    );

    assert!(
        result.is_err(),
        "Auth mode single-shot encryption must fail closed (B14)"
    );
}

/// Test Auth mode fails closed the same way regardless of which sender keypair is used (B14) —
/// it never distinguished between them anyway (that was the vulnerability).
#[test]
fn test_auth_mode_fails_closed_for_every_sender() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender1_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender 1 key generation should work");

    let sender2_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender 2 key generation should work");

    let plaintext = b"Test message for different senders";
    let aad = b"aad";
    let info = b"info";
    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();

    for sender_keypair in [&sender1_keypair, &sender2_keypair] {
        let result = seal_with_mode(
            &mut kem_ctx,
            recipient_keypair.public_key(),
            info,
            aad,
            plaintext,
            &cipher_suite,
            hpke_crypto.as_ref(),
            &mut rng,
            HpkeMode::Auth,
            None,
            None,
            Some(sender_keypair.secret_key()),
            Some(sender_keypair.public_key()),
            HpkePskWireFormat::default(),
        );
        assert!(
            result.is_err(),
            "Auth mode must fail closed (B14) regardless of which sender keypair is used"
        );
    }
}

/// Test Auth mode parameter validation
///
/// These checks still hold: they fail during parameter validation inside
/// `setup_sender_with_mode` *before* the call ever reaches `PostQuantumProvider::auth_encapsulate`
/// (which now fails closed unconditionally anyway).
#[test]
fn test_auth_mode_parameter_validation() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

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
    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();

    // Test missing sender secret key
    let result = setup_sender_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        b"info",
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        None, // Missing sender secret key
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
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
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        None, // Missing sender public key
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
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
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        Some(psk), // Invalid for Auth mode
        Some(psk_id),
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    );
    assert!(result.is_err(), "PSK should not be allowed in Auth mode");
}

/// Test Auth mode fails closed (B14) across different cipher suites — the interim fix must not be
/// suite-specific.
#[test]
fn test_auth_mode_fails_closed_for_different_cipher_suites() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    let plaintext = b"Test message";
    let aad = b"aad";
    let info = b"info";
    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();

    // ML-KEM-512 + HKDF-SHAKE256 + Saturnin-256
    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");
    let suite1 = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );
    let result1 = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &suite1,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    );
    assert!(
        result1.is_err(),
        "Auth mode must fail closed (B14) for suite 1"
    );

    // ML-KEM-768 + HKDF-SHA3-256 + Saturnin-256
    let recipient_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 recipient key generation should work");
    let sender_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("ML-KEM-768 sender key generation should work");
    let suite2 = HpkeCipherSuite::new(
        HpkeKem::MlKem768,
        HpkeKdf::HkdfSha3_256,
        HpkeAead::Saturnin256,
    );
    let result2 = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair_768.public_key(),
        info,
        aad,
        plaintext,
        &suite2,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair_768.secret_key()),
        Some(sender_keypair_768.public_key()),
        HpkePskWireFormat::default(),
    );
    assert!(
        result2.is_err(),
        "Auth mode must fail closed (B14) for suite 2"
    );
}

/// Test Auth mode vs Base mode: Base mode still works; Auth mode fails closed (B14).
#[test]
fn test_auth_mode_fails_closed_while_base_mode_still_works() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);
    let hpke_crypto: Arc<dyn HpkeCryptoProvider + Send + Sync> =
        Arc::new(PostQuantumProvider::new());

    let cipher_suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let plaintext = b"Test message for mode comparison";
    let aad = b"aad";
    let info = b"info";
    let mut rng = lib_q_hpke::security::test_rng::TestRng::new();

    // Base mode: still fully functional.
    let (enc_base, cipher_base) = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Base,
        None,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
    )
    .expect("Base mode encryption should work");

    let dec_base = open_with_mode(
        &mut kem_ctx,
        &enc_base,
        recipient_keypair.secret_key(),
        info,
        aad,
        &cipher_base,
        &cipher_suite,
        hpke_crypto.as_ref(),
        HpkeMode::Base,
        None,
        None,
        None,
        HpkePskWireFormat::default(),
        hpke_crypto.clone(),
    )
    .expect("Base mode decryption should work");
    assert_eq!(dec_base, plaintext);

    // Auth mode: fails closed (B14).
    let auth_result = seal_with_mode(
        &mut kem_ctx,
        recipient_keypair.public_key(),
        info,
        aad,
        plaintext,
        &cipher_suite,
        hpke_crypto.as_ref(),
        &mut rng,
        HpkeMode::Auth,
        None,
        None,
        Some(sender_keypair.secret_key()),
        Some(sender_keypair.public_key()),
        HpkePskWireFormat::default(),
    );
    assert!(
        auth_result.is_err(),
        "Auth mode must fail closed (B14) even though Base mode with the same cipher suite works"
    );
}
