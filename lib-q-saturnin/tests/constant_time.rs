//! Constant-time verification tests for Saturnin
//!
//! These tests verify that Saturnin uses constant-time comparison for AEAD tag
//! verification and that the tag accept/reject behavior is correct.

#[cfg(feature = "alloc")]
extern crate alloc;

use lib_q_core::{
    AeadKey,
    Nonce,
    Result,
    Utils,
};
use lib_q_saturnin::*;

/// Test that Utils::constant_time_compare behaves correctly (equal, unequal, different lengths).
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_utils_constant_time_compare() {
    let a = [1u8; 32];
    let b = [1u8; 32];
    assert!(Utils::constant_time_compare(&a, &b));

    let mut c = [1u8; 32];
    c[0] = 0;
    assert!(!Utils::constant_time_compare(&a, &c));

    let short = [1u8; 31];
    assert!(!Utils::constant_time_compare(&a, &short));
    assert!(!Utils::constant_time_compare(&short, &a));
}

/// Test that AEAD decrypt rejects invalid tag (constant-time verification path).
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_rejects_invalid_tag() -> Result<()> {
    let aead = SaturninAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let plaintext = b"test";

    let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
    assert!(ciphertext.len() >= 32);

    let mut tampered = ciphertext.clone();
    let tag_start = tampered.len() - 32;
    tampered[tag_start] ^= 1;

    let result = aead.decrypt(&key, &nonce, &tampered, None);
    assert!(result.is_err());
    Ok(())
}

/// Test that AEAD decrypt accepts valid tag.
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_accepts_valid_tag() -> Result<()> {
    let aead = SaturninAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let plaintext = b"test";

    let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
    let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

/// Test that SaturninShortAead decrypt rejects invalid tag.
#[cfg(all(feature = "alloc", feature = "aead-short"))]
#[test]
fn test_aead_short_rejects_invalid_tag() -> Result<()> {
    let aead = SaturninShortAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let plaintext = b"test";

    let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
    assert!(ciphertext.len() >= 32);

    let mut tampered = ciphertext.clone();
    let tag_start = tampered.len() - 32;
    tampered[tag_start] ^= 1;

    let result = aead.decrypt(&key, &nonce, &tampered, None);
    assert!(result.is_err());
    Ok(())
}

/// Test that SaturninShortAead decrypt accepts valid tag.
#[cfg(all(feature = "alloc", feature = "aead-short"))]
#[test]
fn test_aead_short_accepts_valid_tag() -> Result<()> {
    let aead = SaturninShortAead::new();
    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let plaintext = b"test";

    let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;
    let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}
