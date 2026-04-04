//! `lib_q_core::Aead` validation branches for [`RomulusNAead`] / [`RomulusMAead`] (sizes, truncated CT).

#![cfg(feature = "alloc")]

use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
};
use lib_q_romulus::{
    RomulusMAead,
    RomulusNAead,
};

#[test]
fn romulus_n_aead_invalid_key_size() {
    let aead = RomulusNAead::new();
    let key = AeadKey::new(vec![0u8; 15]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let r = aead.encrypt(&key, &nonce, b"x", None);
    assert!(matches!(r, Err(Error::InvalidKeySize { .. })));
}

#[test]
fn romulus_n_aead_invalid_nonce_size() {
    let aead = RomulusNAead::new();
    let key = AeadKey::new(vec![0u8; 16]);
    let nonce = Nonce::new(vec![0u8; 15]);
    let r = aead.encrypt(&key, &nonce, b"x", None);
    assert!(matches!(r, Err(Error::InvalidNonceSize { .. })));
}

#[test]
fn romulus_n_aead_ciphertext_shorter_than_tag() {
    let aead = RomulusNAead::new();
    let key = AeadKey::new(vec![1u8; 16]);
    let nonce = Nonce::new(vec![2u8; 16]);
    let r = aead.decrypt(&key, &nonce, b"short", None);
    assert!(matches!(r, Err(Error::VerificationFailed { .. })));
}

#[test]
fn romulus_m_aead_invalid_key_size() {
    let aead = RomulusMAead::new();
    let key = AeadKey::new(vec![0u8; 17]);
    let nonce = Nonce::new(vec![0u8; 16]);
    let r = aead.encrypt(&key, &nonce, b"y", None);
    assert!(matches!(r, Err(Error::InvalidKeySize { .. })));
}

#[test]
fn romulus_m_aead_invalid_nonce_size() {
    let aead = RomulusMAead::new();
    let key = AeadKey::new(vec![0u8; 16]);
    let nonce = Nonce::new(vec![0u8; 17]);
    let r = aead.encrypt(&key, &nonce, b"y", None);
    assert!(matches!(r, Err(Error::InvalidNonceSize { .. })));
}

#[test]
fn romulus_m_aead_ciphertext_shorter_than_tag() {
    let aead = RomulusMAead::new();
    let key = AeadKey::new(vec![3u8; 16]);
    let nonce = Nonce::new(vec![4u8; 16]);
    let r = aead.decrypt(&key, &nonce, &[0u8; 8], None);
    assert!(matches!(r, Err(Error::VerificationFailed { .. })));
}

#[test]
fn romulus_facade_size_constants() {
    assert_eq!(RomulusNAead::key_size(), 16);
    assert_eq!(RomulusNAead::nonce_size(), 16);
    assert_eq!(RomulusNAead::tag_size(), 16);
    assert_eq!(RomulusMAead::key_size(), 16);
    assert_eq!(RomulusMAead::nonce_size(), 16);
    assert_eq!(RomulusMAead::tag_size(), 16);
}
