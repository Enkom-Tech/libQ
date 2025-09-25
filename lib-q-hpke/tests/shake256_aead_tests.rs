#![cfg(feature = "std")]
#![allow(clippy::unnecessary_unwrap)]

use lib_q_hpke::providers::post_quantum::PostQuantumProvider;
use lib_q_hpke::providers::traits::AeadProvider;
use lib_q_hpke::{
    HpkeAead,
    HpkeCipherSuite,
    HpkeKdf,
    HpkeKem,
};

/// Test SHAKE256 AEAD seal operation
#[test]
fn test_shake256_aead_seal() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    let result = provider.seal(HpkeAead::Shake256, key, nonce, aad, plaintext);

    assert!(result.is_ok(), "SHAKE256 AEAD seal should work");
    let ciphertext = result.unwrap();
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert_ne!(
        ciphertext, plaintext,
        "Ciphertext should be different from plaintext"
    );
}

/// Test SHAKE256 AEAD open operation
#[test]
fn test_shake256_aead_open() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    // First seal the message
    let ciphertext = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("Seal should work");

    // Then open it
    let result = provider.open(HpkeAead::Shake256, key, nonce, aad, &ciphertext);

    assert!(result.is_ok(), "SHAKE256 AEAD open should work");
    let decrypted = result.unwrap();
    assert_eq!(
        decrypted, plaintext,
        "Decrypted should match original plaintext"
    );
}

/// Test SHAKE256 AEAD with different key sizes
#[test]
fn test_shake256_aead_different_key_sizes() {
    let provider = PostQuantumProvider::new();
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Test message";

    // Test with 32-byte key (standard)
    let key_32 = &[1u8; 32]; // Exactly 32 bytes
    let result_32 = provider.seal(HpkeAead::Shake256, key_32, nonce, aad, plaintext);
    assert!(result_32.is_ok(), "32-byte key should work");

    // Test with 16-byte key (should fail or be handled)
    let key_16 = b"test_key_16_bytes";
    let result_16 = provider.seal(HpkeAead::Shake256, key_16, nonce, aad, plaintext);
    // This might fail due to key size requirements
    if result_16.is_err() {
        let error = result_16.unwrap_err();
        assert!(
            error.to_string().contains("key") ||
                error.to_string().contains("size") ||
                error.to_string().contains("length"),
            "Error should mention key size: {}",
            error
        );
    }
}

/// Test SHAKE256 AEAD with different nonce sizes
#[test]
fn test_shake256_aead_different_nonce_sizes() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Test message";

    // Test with 16-byte nonce (standard)
    let nonce_16 = &[0u8; 16]; // Exactly 16 bytes
    let result_16 = provider.seal(HpkeAead::Shake256, key, nonce_16, aad, plaintext);
    assert!(result_16.is_ok(), "16-byte nonce should work");

    // Test with 12-byte nonce (might be supported)
    let nonce_12 = b"test_nonce_12";
    let result_12 = provider.seal(HpkeAead::Shake256, key, nonce_12, aad, plaintext);
    // This might fail due to nonce size requirements
    if result_12.is_err() {
        let error = result_12.unwrap_err();
        assert!(
            error.to_string().contains("nonce") ||
                error.to_string().contains("size") ||
                error.to_string().contains("length"),
            "Error should mention nonce size: {}",
            error
        );
    }
}

/// Test SHAKE256 AEAD with empty plaintext
#[test]
fn test_shake256_aead_empty_plaintext() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"";

    let result = provider.seal(HpkeAead::Shake256, key, nonce, aad, plaintext);

    assert!(result.is_ok(), "Empty plaintext should be supported");
    let ciphertext = result.unwrap();

    // Even empty plaintext should produce some ciphertext (at least authentication tag)
    assert!(
        !ciphertext.is_empty(),
        "Empty plaintext should still produce ciphertext"
    );
}

/// Test SHAKE256 AEAD with empty AAD
#[test]
fn test_shake256_aead_empty_aad() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"";
    let plaintext = b"Test message";

    let result = provider.seal(HpkeAead::Shake256, key, nonce, aad, plaintext);

    assert!(result.is_ok(), "Empty AAD should be supported");
    let ciphertext = result.unwrap();
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
}

/// Test SHAKE256 AEAD authentication failure
#[test]
fn test_shake256_aead_authentication_failure() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    // Seal the message
    let ciphertext = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("Seal should work");

    // Try to open with wrong key
    let wrong_key = &[2u8; 32]; // Exactly 32 bytes
    let result = provider.open(HpkeAead::Shake256, wrong_key, nonce, aad, &ciphertext);

    assert!(result.is_err(), "Opening with wrong key should fail");
}

/// Test SHAKE256 AEAD with wrong nonce
#[test]
fn test_shake256_aead_wrong_nonce() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    // Seal the message
    let ciphertext = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("Seal should work");

    // Try to open with wrong nonce
    let wrong_nonce = &[1u8; 16]; // Exactly 16 bytes
    let result = provider.open(HpkeAead::Shake256, key, wrong_nonce, aad, &ciphertext);

    assert!(result.is_err(), "Opening with wrong nonce should fail");
}

/// Test SHAKE256 AEAD with wrong AAD
#[test]
fn test_shake256_aead_wrong_aad() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    // Seal the message
    let ciphertext = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("Seal should work");

    // Try to open with wrong AAD
    let wrong_aad = b"wrong_authenticated_data";
    let result = provider.open(HpkeAead::Shake256, key, nonce, wrong_aad, &ciphertext);

    assert!(result.is_err(), "Opening with wrong AAD should fail");
}

/// Test SHAKE256 AEAD in HPKE context
#[test]
fn test_shake256_aead_in_hpke_context() {
    let cipher_suite =
        HpkeCipherSuite::new(HpkeKem::MlKem512, HpkeKdf::HkdfShake256, HpkeAead::Shake256);

    // Test that the cipher suite can be created
    assert_eq!(cipher_suite.aead, HpkeAead::Shake256);

    // Test that the AEAD has correct properties
    assert_eq!(cipher_suite.aead.key_len(), 32); // SHAKE256 should use 32-byte keys
    assert_eq!(cipher_suite.aead.nonce_len(), 16); // Standard nonce length
}

/// Test SHAKE256 AEAD non-determinism (should be different due to secure RNG)
#[test]
fn test_shake256_aead_determinism() {
    let provider = PostQuantumProvider::new();
    let key = &[1u8; 32]; // Exactly 32 bytes
    let nonce = &[0u8; 16]; // Exactly 16 bytes
    let aad = b"additional_authenticated_data";
    let plaintext = b"Hello, SHAKE256 AEAD!";

    // Encrypt the same message twice
    let ciphertext1 = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("First seal should work");

    let ciphertext2 = provider
        .seal(HpkeAead::Shake256, key, nonce, aad, plaintext)
        .expect("Second seal should work");

    // The ciphertexts should be different (due to secure random IV generation)
    assert_ne!(
        ciphertext1, ciphertext2,
        "Ciphertexts should be different due to secure random IV generation"
    );

    // Both should decrypt to the same plaintext
    let decrypted1 = provider
        .open(HpkeAead::Shake256, key, nonce, aad, &ciphertext1)
        .expect("First open should work");

    let decrypted2 = provider
        .open(HpkeAead::Shake256, key, nonce, aad, &ciphertext2)
        .expect("Second open should work");

    assert_eq!(
        decrypted1, plaintext,
        "First decryption should match original"
    );
    assert_eq!(
        decrypted2, plaintext,
        "Second decryption should match original"
    );
}
