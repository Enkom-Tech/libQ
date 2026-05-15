//! `lib_q_core::Aead` validation branches for [`RomulusNAead`] / [`RomulusMAead`] (sizes, truncated CT).

#![cfg(feature = "alloc")]

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
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
    assert!(matches!(r, Err(Error::InvalidCiphertextSize { .. })));
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
    assert!(matches!(r, Err(Error::InvalidCiphertextSize { .. })));
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

#[test]
fn romulus_n_decrypt_semantic_tampered_tag() {
    let aead = RomulusNAead::new();
    let key = AeadKey::new(vec![0x11u8; 16]);
    let nonce = Nonce::new(vec![0x22u8; 16]);
    let pt = b"romulus-n-msg";
    let mut ct = aead.encrypt(&key, &nonce, pt, None).expect("encrypt");
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let out = aead
        .decrypt_semantic(&key, &nonce, &ct, None)
        .expect("semantic decrypt operational");
    assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
}

#[test]
fn romulus_n_decrypt_semantic_success_matches_layer_a() {
    let aead = RomulusNAead::new();
    let key = AeadKey::new(vec![0x33u8; 16]);
    let nonce = Nonce::new(vec![0x44u8; 16]);
    let ad = b"ad";
    let pt = b"body";
    let ct = aead.encrypt(&key, &nonce, pt, Some(ad)).expect("encrypt");
    let layer_a = aead.decrypt(&key, &nonce, &ct, Some(ad)).expect("decrypt");
    match aead
        .decrypt_semantic(&key, &nonce, &ct, Some(ad))
        .expect("decrypt_semantic")
    {
        DecryptSemanticOutcome::Success(got) => assert_eq!(got.as_slice(), layer_a.as_slice()),
        DecryptSemanticOutcome::AuthenticationFailed => panic!("expected Success"),
    }
}

#[test]
fn romulus_m_decrypt_semantic_tampered_tag() {
    let aead = RomulusMAead::new();
    let key = AeadKey::new(vec![0x55u8; 16]);
    let nonce = Nonce::new(vec![0x66u8; 16]);
    let pt = b"romulus-m-msg";
    let mut ct = aead.encrypt(&key, &nonce, pt, None).expect("encrypt");
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let out = aead
        .decrypt_semantic(&key, &nonce, &ct, None)
        .expect("semantic decrypt operational");
    assert_eq!(out, DecryptSemanticOutcome::AuthenticationFailed);
}
