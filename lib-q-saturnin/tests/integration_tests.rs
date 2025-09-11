//! Integration tests for Saturnin algorithms

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use lib_q_core::{
    AeadKey,
    Hash,
    Nonce,
    Result,
};
use lib_q_saturnin::*;

/// Test AEAD round-trip encryption/decryption
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_round_trip() -> Result<()> {
    let aead = SaturninAead::new();

    // Test with various message sizes (CTR-Cascade supports arbitrary lengths)
    let test_cases = vec![
        b"".as_slice(),
        b"a".as_slice(),
        b"test".as_slice(),
        b"Hello, World!".as_slice(), // 13 bytes
        b"This is a longer message to test CTR-Cascade mode".as_slice(), // 50 bytes
    ];

    for plaintext in test_cases {
        let key = AeadKey::new(vec![0u8; 32]);
        let nonce = Nonce::new(vec![0u8; 16]);

        // Encrypt (CTR-Cascade supports associated data)
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, None)?;

        // Verify ciphertext is plaintext length + 32 bytes (tag)
        assert_eq!(ciphertext.len(), plaintext.len() + 32);

        // Decrypt
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, None)?;
        assert_eq!(decrypted, plaintext);
    }

    Ok(())
}

/// Test AEAD authentication failure
#[cfg(all(feature = "alloc", feature = "aead"))]
#[test]
fn test_aead_auth_failure() -> Result<()> {
    let aead = SaturninAead::new();

    let key = AeadKey::new(vec![0u8; 32]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let plaintext = b"Secret message"; // 14 bytes - test with CTR-Cascade
    let ad_data = b"metadata"; // Associated data

    // Encrypt with associated data
    let ciphertext = aead.encrypt(&key, &nonce, plaintext, Some(ad_data))?;

    // Try to decrypt with wrong associated data
    let wrong_ad = b"wrong metadata";
    let result = aead.decrypt(&key, &nonce, &ciphertext, Some(wrong_ad));
    assert!(result.is_err(), "Should fail with wrong associated data");

    // Try to decrypt with tampered ciphertext
    let mut tampered_ciphertext = ciphertext.clone();
    if !tampered_ciphertext.is_empty() {
        tampered_ciphertext[0] ^= 1;
    }
    let result = aead.decrypt(&key, &nonce, &tampered_ciphertext, Some(ad_data));
    assert!(result.is_err(), "Should fail with tampered ciphertext");

    Ok(())
}

/// Test Hash with various input sizes
#[cfg(all(feature = "alloc", feature = "hash"))]
#[test]
fn test_hash_various_sizes() -> Result<()> {
    let hash = SaturninHash::new();

    // Test empty input
    let empty_hash = hash.hash(b"")?;
    assert_eq!(empty_hash.len(), 32);

    // Test single byte
    let single_byte_hash = hash.hash(b"a")?;
    assert_eq!(single_byte_hash.len(), 32);
    assert_ne!(empty_hash, single_byte_hash);

    // Test large input
    let large_input = vec![0u8; 10000];
    let large_hash = hash.hash(&large_input)?;
    assert_eq!(large_hash.len(), 32);

    // Test that same input produces same hash
    let hash1 = hash.hash(b"test message")?;
    let hash2 = hash.hash(b"test message")?;
    assert_eq!(hash1, hash2);

    // Test that different inputs produce different hashes
    let hash3 = hash.hash(b"different message")?;
    assert_ne!(hash1, hash3);

    Ok(())
}

/// Test Block Cipher round-trip
#[cfg(all(feature = "alloc", feature = "block-cipher"))]
#[test]
fn test_block_cipher_round_trip() -> Result<()> {
    let cipher = SaturninBlockCipher::new();

    let key = vec![0u8; 32];
    let plaintext = vec![0u8; 32];

    // Encrypt
    let ciphertext = cipher.encrypt_block(&key, &plaintext)?;
    assert_eq!(ciphertext.len(), 32);

    // Decrypt
    let decrypted = cipher.decrypt_block(&key, &ciphertext)?;
    assert_eq!(decrypted, plaintext);

    // Test with different key
    let different_key = vec![1u8; 32];
    let different_ciphertext = cipher.encrypt_block(&different_key, &plaintext)?;
    assert_ne!(ciphertext, different_ciphertext);

    // Test with different plaintext
    let different_plaintext = vec![1u8; 32];
    let different_ciphertext2 = cipher.encrypt_block(&key, &different_plaintext)?;
    assert_ne!(ciphertext, different_ciphertext2);

    Ok(())
}

/// Test Stream Cipher
#[cfg(all(feature = "alloc", feature = "stream"))]
#[test]
fn test_stream_cipher() -> Result<()> {
    let stream = SaturninStream::new();

    let key = vec![0u8; 32];
    let nonce = vec![0u8; 16];
    let plaintext = b"Hello, World! This is a test message.";

    // Encrypt
    let ciphertext = stream.encrypt(&key, &nonce, plaintext)?;
    assert_eq!(ciphertext.len(), plaintext.len());

    // Decrypt
    let decrypted = stream.decrypt(&key, &nonce, &ciphertext)?;
    assert_eq!(decrypted, plaintext);

    // Test that same input with same key produces same output
    let ciphertext2 = stream.encrypt(&key, &nonce, plaintext)?;
    assert_eq!(ciphertext, ciphertext2);

    Ok(())
}

/// Test no_std compatibility
#[cfg(all(
    not(feature = "std"),
    feature = "aead",
    feature = "hash",
    feature = "block-cipher"
))]
#[test]
fn test_no_std_compatibility() {
    // This test ensures the crate works in no_std environments
    let _aead = SaturninAead::new();
    assert_eq!(SaturninAead::key_size(), 32);
    assert_eq!(SaturninAead::nonce_size(), 16);
    assert_eq!(SaturninAead::tag_size(), 32);

    let hash = SaturninHash::new();
    assert_eq!(hash.output_size(), 32);

    let _cipher = SaturninBlockCipher::new();
    assert_eq!(SaturninBlockCipher::key_size(), 32);
    assert_eq!(SaturninBlockCipher::block_size(), 32);
}
