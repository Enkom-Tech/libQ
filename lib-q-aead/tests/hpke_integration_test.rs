//! HPKE Integration Test
//!
//! This test verifies that our AEAD implementations work correctly with the HPKE system.

#[cfg(feature = "shake256")]
use lib_q_aead::{
    AeadKey,
    Algorithm,
    Nonce,
    create_aead,
};

/// Generate a proper test key with good entropy
fn create_test_key() -> AeadKey {
    AeadKey::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ])
}

/// Generate a proper test nonce with good entropy
fn create_test_nonce() -> Nonce {
    Nonce::new(vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ])
}

#[cfg(feature = "shake256")]
#[test]
fn test_hpke_shake256_integration() {
    // Test that we can create a SHAKE256 AEAD instance
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    // Test HPKE-compatible key and nonce sizes
    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, HPKE!";
    let aad = b"hpke-info";

    // Encrypt
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("SHAKE256 encryption failed");

    // Verify ciphertext is longer than plaintext (due to authentication tag)
    assert!(ciphertext.len() > plaintext.len());
    assert_ne!(ciphertext, plaintext);

    // Decrypt
    let decrypted = aead
        .decrypt(&key, &nonce, &ciphertext, Some(aad))
        .expect("SHAKE256 decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[cfg(feature = "shake256")]
#[test]
fn test_hpke_shake256_key_validation() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    // Test valid key size (32 bytes)
    let valid_key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"test";
    let aad = b"test";

    let result = aead.encrypt(&valid_key, &nonce, plaintext, Some(aad));
    assert!(result.is_ok(), "Valid key should work");

    // Test invalid key size (16 bytes)
    let invalid_key = AeadKey::new(vec![1u8; 16]);
    let result = aead.encrypt(&invalid_key, &nonce, plaintext, Some(aad));
    assert!(result.is_err(), "Invalid key size should fail");
}

#[cfg(feature = "shake256")]
#[test]
fn test_hpke_shake256_nonce_validation() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    // Test valid nonce size (16 bytes)
    let key = create_test_key();
    let valid_nonce = create_test_nonce();
    let plaintext = b"test";
    let aad = b"test";

    let result = aead.encrypt(&key, &valid_nonce, plaintext, Some(aad));
    assert!(result.is_ok(), "Valid nonce should work");

    // Test invalid nonce size (12 bytes)
    let invalid_nonce = Nonce::new(vec![2u8; 12]);
    let result = aead.encrypt(&key, &invalid_nonce, plaintext, Some(aad));
    assert!(result.is_err(), "Invalid nonce size should fail");
}

#[cfg(feature = "shake256")]
#[test]
fn test_hpke_shake256_authentication() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, HPKE!";
    let aad = b"hpke-info";

    // Encrypt
    let ciphertext = aead
        .encrypt(&key, &nonce, plaintext, Some(aad))
        .expect("SHAKE256 encryption failed");

    // Tamper with ciphertext
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;

    // Decrypt should fail
    let result = aead.decrypt(&key, &nonce, &tampered, Some(aad));
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail to decrypt"
    );
}

#[cfg(feature = "shake256")]
#[test]
fn test_hpke_shake256_domain_separation() {
    let aead = create_aead(Algorithm::Shake256Aead).expect("Failed to create SHAKE256 AEAD");

    let key = create_test_key();
    let nonce = create_test_nonce();
    let plaintext = b"Hello, HPKE!";

    // Encrypt with different AAD should produce different ciphertexts
    let ciphertext1 = aead
        .encrypt(&key, &nonce, plaintext, Some(b"aad1"))
        .expect("SHAKE256 encryption failed");
    let ciphertext2 = aead
        .encrypt(&key, &nonce, plaintext, Some(b"aad2"))
        .expect("SHAKE256 encryption failed");

    // Should be different due to domain separation
    assert_ne!(ciphertext1, ciphertext2);

    // Both should decrypt correctly with their respective AAD
    let decrypted1 = aead
        .decrypt(&key, &nonce, &ciphertext1, Some(b"aad1"))
        .expect("SHAKE256 decryption failed");
    let decrypted2 = aead
        .decrypt(&key, &nonce, &ciphertext2, Some(b"aad2"))
        .expect("SHAKE256 decryption failed");

    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
}
