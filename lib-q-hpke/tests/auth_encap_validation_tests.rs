//! Comprehensive tests for AuthEncap/AuthDecap implementation validation
//!
//! These tests validate that the authentication implementation provides proper
//! cryptographic authentication guarantees as required by RFC 9180.

#![cfg(feature = "std")]
#![allow(unused_imports, unused_variables)]

use lib_q_core::{
    Algorithm,
    Kem,
    KemContext,
    KemPublicKey,
    KemSecretKey,
};
use lib_q_hpke::HpkeKem;
use lib_q_hpke::providers::KemProvider;
use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::security::CryptoRng;
use lib_q_kem::LibQKemProvider;

/// Test that AuthEncap/AuthDecap provides proper sender authentication
#[test]
fn test_auth_encap_auth_decap_authentication() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate sender and recipient key pairs
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    // Test AuthEncap/AuthDecap with proper validation
    let hpke_provider = PostQuantumProvider::new();

    // Test AuthEncap
    let auth_encap_result = hpke_provider.auth_encapsulate(
        HpkeKem::MlKem512,
        sender_keypair.secret_key().as_bytes(),
        recipient_keypair.public_key().as_bytes(),
        &mut TestRng,
    );

    assert!(auth_encap_result.is_ok(), "AuthEncap should succeed");
    let (encapsulated_key, shared_secret) = auth_encap_result.unwrap();

    // Test AuthDecap
    let auth_decap_result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        sender_keypair.public_key().as_bytes(),
    );

    assert!(auth_decap_result.is_ok(), "AuthDecap should succeed");
    let decapsulated_shared_secret = auth_decap_result.unwrap();

    // Verify that the shared secrets match
    assert_eq!(
        shared_secret, decapsulated_shared_secret,
        "Shared secrets should match between AuthEncap and AuthDecap"
    );
}

/// Test that AuthDecap fails with incorrect sender public key
#[test]
fn test_auth_decap_fails_with_wrong_sender() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate three key pairs: sender, recipient, and wrong sender
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let wrong_sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Wrong sender key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Perform AuthEncap with correct sender
    let (encapsulated_key, _shared_secret) = hpke_provider
        .auth_encapsulate(
            HpkeKem::MlKem512,
            sender_keypair.secret_key().as_bytes(),
            recipient_keypair.public_key().as_bytes(),
            &mut TestRng,
        )
        .expect("AuthEncap should succeed");

    // Try AuthDecap with wrong sender public key
    let auth_decap_result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        wrong_sender_keypair.public_key().as_bytes(), // Wrong sender!
    );

    // This should fail because the authentication won't match
    assert!(
        auth_decap_result.is_err(),
        "AuthDecap should fail with wrong sender public key"
    );
}

/// Test that AuthEncap/AuthDecap works with different ML-KEM variants
#[test]
fn test_auth_encap_auth_decap_ml_kem_variants() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    let hpke_provider = PostQuantumProvider::new();

    // Test with ML-KEM-768
    let sender_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("Sender key generation should work");

    let recipient_keypair_768 = kem_ctx
        .generate_keypair(Algorithm::MlKem768, None)
        .expect("Recipient key generation should work");

    let (encapsulated_key_768, shared_secret_768) = hpke_provider
        .auth_encapsulate(
            HpkeKem::MlKem768,
            sender_keypair_768.secret_key().as_bytes(),
            recipient_keypair_768.public_key().as_bytes(),
            &mut TestRng,
        )
        .expect("AuthEncap should succeed");

    let decapsulated_shared_secret_768 = hpke_provider
        .auth_decapsulate(
            HpkeKem::MlKem768,
            &encapsulated_key_768,
            recipient_keypair_768.secret_key().as_bytes(),
            sender_keypair_768.public_key().as_bytes(),
        )
        .expect("AuthDecap should succeed");

    assert_eq!(
        shared_secret_768, decapsulated_shared_secret_768,
        "ML-KEM-768 shared secrets should match"
    );

    // Test with ML-KEM-1024
    let sender_keypair_1024 = kem_ctx
        .generate_keypair(Algorithm::MlKem1024, None)
        .expect("Sender key generation should work");

    let recipient_keypair_1024 = kem_ctx
        .generate_keypair(Algorithm::MlKem1024, None)
        .expect("Recipient key generation should work");

    let (encapsulated_key_1024, shared_secret_1024) = hpke_provider
        .auth_encapsulate(
            HpkeKem::MlKem1024,
            sender_keypair_1024.secret_key().as_bytes(),
            recipient_keypair_1024.public_key().as_bytes(),
            &mut TestRng,
        )
        .expect("AuthEncap should succeed");

    let decapsulated_shared_secret_1024 = hpke_provider
        .auth_decapsulate(
            HpkeKem::MlKem1024,
            &encapsulated_key_1024,
            recipient_keypair_1024.secret_key().as_bytes(),
            sender_keypair_1024.public_key().as_bytes(),
        )
        .expect("AuthDecap should succeed");

    assert_eq!(
        shared_secret_1024, decapsulated_shared_secret_1024,
        "ML-KEM-1024 shared secrets should match"
    );
}

/// Test that derive_public_key works correctly
#[test]
fn test_derive_public_key() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate a key pair
    let keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Test that we can derive the public key from the secret key
    // This is used internally by auth_encapsulate
    let kem_impl = lib_q_kem::ml_kem::MlKem512Impl::default();

    let derived_public_key = kem_impl
        .derive_public_key(&lib_q_core::KemSecretKey::new(
            keypair.secret_key().as_bytes().to_vec(),
        ))
        .expect("Should be able to derive public key");

    // The derived public key should match the original public key
    assert_eq!(
        derived_public_key.data,
        keypair.public_key().as_bytes(),
        "Derived public key should match original public key"
    );
}

/// Test that authentication provides cryptographic proof of sender identity
#[test]
fn test_authentication_cryptographic_proof() {
    let provider = Box::new(LibQKemProvider::new().expect("Failed to create KEM provider"));
    let mut kem_ctx = KemContext::with_provider(provider);

    // Generate sender and recipient key pairs
    let sender_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Sender key generation should work");

    let recipient_keypair = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("Recipient key generation should work");

    let hpke_provider = PostQuantumProvider::new();

    // Perform AuthEncap
    let (encapsulated_key, shared_secret) = hpke_provider
        .auth_encapsulate(
            HpkeKem::MlKem512,
            sender_keypair.secret_key().as_bytes(),
            recipient_keypair.public_key().as_bytes(),
            &mut TestRng,
        )
        .expect("AuthEncap should succeed");

    // Perform standard encapsulation for comparison
    let kem_impl = lib_q_kem::ml_kem::MlKem512Impl::default();

    let (standard_encapsulated_key, standard_shared_secret) = kem_impl
        .encapsulate(&lib_q_core::KemPublicKey::new(
            recipient_keypair.public_key().as_bytes().to_vec(),
        ))
        .expect("Standard encapsulation should succeed");

    // The encapsulated keys should be different (authentication adds sender identity)
    assert_ne!(
        encapsulated_key, standard_encapsulated_key,
        "Authenticated encapsulated key should be different from standard encapsulated key"
    );

    // The shared secrets should be different (authentication modifies the shared secret)
    assert_ne!(
        shared_secret, standard_shared_secret,
        "Authenticated shared secret should be different from standard shared secret"
    );

    // Verify that AuthDecap works with the authenticated version
    let auth_decap_result = hpke_provider.auth_decapsulate(
        HpkeKem::MlKem512,
        &encapsulated_key,
        recipient_keypair.secret_key().as_bytes(),
        sender_keypair.public_key().as_bytes(),
    );

    assert!(auth_decap_result.is_ok(), "AuthDecap should succeed");
    let decapsulated_shared_secret = auth_decap_result.unwrap();

    assert_eq!(
        shared_secret, decapsulated_shared_secret,
        "Authenticated shared secrets should match"
    );
}

/// Simple test RNG for testing purposes
struct TestRng;

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), lib_q_hpke::error::HpkeError> {
        // For testing, we don't need actual randomness
        // The ML-KEM implementation will use its own RNG
        // Fill with deterministic pattern for reproducible tests
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x42);
        }
        Ok(())
    }

    fn next_u32(&mut self) -> Result<u32, lib_q_hpke::error::HpkeError> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn next_u64(&mut self) -> Result<u64, lib_q_hpke::error::HpkeError> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}
