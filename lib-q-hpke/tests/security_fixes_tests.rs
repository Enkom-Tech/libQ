//! Tests to verify critical security fixes

#![cfg(feature = "std")]
#![allow(clippy::assertions_on_constants)]

use lib_q_core::{
    Algorithm,
    KemContext,
};
use lib_q_hpke::providers::KemProvider;
use lib_q_hpke::security::CryptoRng;
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeContext,
    HpkeKdf,
    HpkeKem,
};
use lib_q_kem::LibQKemProvider;

/// Test that KT128-based RNG is available and working
#[test]
fn test_kangaroo_twelve_rng_availability() {
    #[cfg(feature = "hash")]
    {
        use lib_q_hpke::security::prng::Kt128Rng;

        let rng = Kt128Rng::new();
        assert!(
            rng.is_ok(),
            "KT128 RNG should be available with hash feature"
        );

        let mut rng = rng.unwrap();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes).unwrap();

        // Verify we got random bytes (very unlikely to be all zeros or all same value)
        assert!(
            bytes.iter().any(|&b| b != 0),
            "K12 RNG should produce non-zero bytes"
        );
        assert!(
            bytes.iter().any(|&b| b != bytes[0]),
            "K12 RNG should produce varied bytes"
        );

        // Test deterministic behavior with same seed
        let seed = b"test seed for K12 RNG";
        let mut rng1 = Kt128Rng::from_seed(seed);
        let mut rng2 = Kt128Rng::from_seed(seed);

        let mut bytes1 = [0u8; 16];
        let mut bytes2 = [0u8; 16];
        rng1.fill_bytes(&mut bytes1).unwrap();
        rng2.fill_bytes(&mut bytes2).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "K12 RNG should be deterministic with same seed"
        );
    }

    #[cfg(not(feature = "hash"))]
    {
        use lib_q_hpke::security::prng::fill_random_bytes;

        let mut bytes = [0u8; 32];
        // With secure-rng (getrandom), fill_random_bytes succeeds; otherwise it returns Err
        if fill_random_bytes(&mut bytes).is_ok() {
            assert!(
                bytes.iter().any(|&b| b != 0),
                "RNG should produce non-zero bytes"
            );
        }
    }
}

/// B14 interim fix: Auth mode used to look "fixed" here only because the round trip completed —
/// it never actually bound a sender secret key (see `lib-q-hpke/tests/auth_encap_validation_tests.rs`'s
/// `auth_decapsulate_rejects_forged_sender_identity_with_no_sender_secret_key`). It is now
/// disabled and fails closed for valid keys just as it does for invalid ones.
#[test]
fn test_auth_encap_auth_decap_fixes() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate sender and recipient key pairs
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let hpke_provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();

    let auth_encap_result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        sender_keypair.secret_key().as_bytes(),
        recipient_keypair.public_key().as_bytes(),
        &mut lib_q_hpke::security::test_rng::TestRng::new(),
    );

    assert!(
        auth_encap_result.is_err(),
        "AuthEncap must fail closed (B14) even with entirely valid keys"
    );

    // No valid authenticated encapsulated key can be produced anymore; AuthDecap fails closed on
    // a well-formed-sized placeholder too.
    let placeholder_encapsulated_key = vec![0u8; HpkeKem::MlKem512.enc_len() + 32];
    let auth_decap_result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &placeholder_encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        sender_keypair.public_key().as_bytes(),
    );

    assert!(
        auth_decap_result.is_err(),
        "AuthDecap must fail closed (B14) even with well-formed-sized input"
    );
}

/// Test that invalid key sizes are properly rejected
/// NOTE (B14): since the interim fix, `auth_encapsulate` fails closed unconditionally, so these
/// assertions no longer specifically exercise size validation — they still pass, now for the same
/// reason as every other `auth_encapsulate` call (see `test_auth_encap_auth_decap_fixes`).
/// Left as `is_err()` checks rather than removed: they document that invalid input still isn't
/// silently accepted, which remains true.
#[test]
fn test_auth_encap_invalid_key_sizes() {
    let hpke_provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();

    // Test with invalid sender key size
    let invalid_sender_sk = vec![0u8; 100]; // Wrong size
    let valid_recipient_pk = vec![0u8; 800]; // Correct ML-KEM-512 size

    let result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        &invalid_sender_sk,
        &valid_recipient_pk,
        &mut lib_q_hpke::security::test_rng::TestRng::new(),
    );

    assert!(
        result.is_err(),
        "AuthEncap should reject invalid sender key size"
    );

    // Test with invalid recipient key size
    let valid_sender_sk = vec![0u8; 1632]; // Correct ML-KEM-512 size
    let invalid_recipient_pk = vec![0u8; 100]; // Wrong size

    let result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        &valid_sender_sk,
        &invalid_recipient_pk,
        &mut lib_q_hpke::security::test_rng::TestRng::new(),
    );

    assert!(
        result.is_err(),
        "AuthEncap should reject invalid recipient key size"
    );
}

/// NOTE (B14): since the interim fix, `auth_decapsulate` fails closed unconditionally, so these
/// assertions no longer specifically exercise size validation — see the note on
/// `test_auth_encap_invalid_key_sizes` above.
#[test]
fn test_auth_decap_invalid_key_sizes() {
    let hpke_provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();

    // Test with invalid encapsulated key size
    let invalid_encapsulated_key = vec![0u8; 100]; // Wrong size
    let valid_recipient_sk = vec![0u8; 1632]; // Correct ML-KEM-512 size
    let valid_sender_pk = vec![0u8; 800]; // Correct ML-KEM-512 size

    let result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &invalid_encapsulated_key,
        &valid_recipient_sk,
        &valid_sender_pk,
    );

    assert!(
        result.is_err(),
        "AuthDecap should reject invalid encapsulated key size"
    );

    // Test with invalid recipient key size
    let valid_encapsulated_key = vec![0u8; HpkeKem::MlKem512.enc_len() + 32]; // ciphertext + auth tag
    let invalid_recipient_sk = vec![0u8; 100]; // Wrong size

    let result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &valid_encapsulated_key,
        &invalid_recipient_sk,
        &valid_sender_pk,
    );

    assert!(
        result.is_err(),
        "AuthDecap should reject invalid recipient key size"
    );

    // Test with invalid sender key size
    let invalid_sender_pk = vec![0u8; 100]; // Wrong size

    let result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &valid_encapsulated_key,
        &valid_recipient_sk,
        &invalid_sender_pk,
    );

    assert!(
        result.is_err(),
        "AuthDecap should reject invalid sender key size"
    );
}

/// Test that HPKE context creation works with secure RNG
#[test]
fn test_hpke_context_with_secure_rng() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let _hpke_ctx = HpkeContext::with_provider(provider);

    // Context creation should not panic
    assert!(true, "HPKE context creation should work");

    // Test that we can create a cipher suite
    let suite = HpkeCipherSuite::new(
        HpkeKem::MlKem512,
        HpkeKdf::HkdfShake256,
        HpkeAead::Saturnin256,
    );

    // Verify suite properties
    assert_eq!(suite.kem, HpkeKem::MlKem512);
    assert_eq!(suite.kdf, HpkeKdf::HkdfShake256);
    assert_eq!(suite.aead, HpkeAead::Saturnin256);
}

/// Test that the implementation properly handles different ML-KEM variants
#[test]
fn test_ml_kem_variants() {
    let _hpke_provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();

    // Test ML-KEM-512
    let kem_512 = HpkeKem::MlKem512;
    assert_eq!(kem_512.public_key_len(), 800);
    assert_eq!(kem_512.secret_key_len(), 1632);
    assert_eq!(kem_512.enc_len(), 768);
    assert_eq!(kem_512.shared_secret_len(), 32);

    // Test ML-KEM-768
    let kem_768 = HpkeKem::MlKem768;
    assert_eq!(kem_768.public_key_len(), 1184);
    assert_eq!(kem_768.secret_key_len(), 2400);
    assert_eq!(kem_768.enc_len(), 1088);
    assert_eq!(kem_768.shared_secret_len(), 32);

    // Test ML-KEM-1024
    let kem_1024 = HpkeKem::MlKem1024;
    assert_eq!(kem_1024.public_key_len(), 1568);
    assert_eq!(kem_1024.secret_key_len(), 3168);
    assert_eq!(kem_1024.enc_len(), 1568);
    assert_eq!(kem_1024.shared_secret_len(), 32);
}

/// Test that error messages don't leak sensitive information
#[test]
fn test_error_message_security() {
    let hpke_provider = lib_q_hpke::providers::post_quantum::PostQuantumProvider::new();

    // Test that error messages don't contain key material
    let invalid_key = vec![0x42u8; 100]; // Some test data
    let result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        &invalid_key,
        &invalid_key,
        &mut lib_q_hpke::security::test_rng::TestRng::new(),
    );

    assert!(result.is_err());
    let error_msg = format!("{}", result.unwrap_err());

    // Error message should not contain the actual key bytes
    assert!(
        !error_msg.contains("424242"),
        "Error message should not leak key material"
    );
    // NOTE (B14): `auth_encapsulate` now fails closed with a fixed, static message (Auth mode is
    // disabled) rather than a per-call size-validation message, so it no longer says "bytes" —
    // check it mentions the actual reason instead.
    assert!(
        error_msg.to_lowercase().contains("auth"),
        "Error message should explain that Auth mode is unavailable"
    );
}
