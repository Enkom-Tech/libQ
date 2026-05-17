//! Negative tests: wrong tag, nonce, AD, truncated ciphertext.

#![cfg(feature = "std")]

use aead::generic_array::GenericArray;
use aead::{
    AeadInPlace,
    KeyInit,
};
use lib_q_romulus::{
    RomulusM,
    RomulusN,
};

#[test]
fn romulus_n_wrong_tag_fails() {
    let key = GenericArray::from([7u8; 16]);
    let nonce = GenericArray::from([8u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"hello romulus".to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"ad", &mut buf)
        .unwrap();
    let mut bad = tag;
    bad[0] ^= 0xFF;
    let err = cipher.decrypt_in_place_detached(&nonce, b"ad", &mut buf, &bad);
    assert!(err.is_err());
    assert!(
        buf.iter().all(|&b| b == 0),
        "plaintext should be cleared on failure"
    );
}

#[test]
fn romulus_n_wrong_nonce_fails() {
    let key = GenericArray::from([1u8; 16]);
    let n1 = GenericArray::from([2u8; 16]);
    let n2 = GenericArray::from([3u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"data".to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&n1, b"", &mut buf)
        .unwrap();
    let err = cipher.decrypt_in_place_detached(&n2, b"", &mut buf, &tag);
    assert!(err.is_err());
}

#[test]
fn romulus_n_wrong_ad_fails() {
    let key = GenericArray::from([4u8; 16]);
    let nonce = GenericArray::from([5u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"x".to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"ad1", &mut buf)
        .unwrap();
    let err = cipher.decrypt_in_place_detached(&nonce, b"ad2", &mut buf, &tag);
    assert!(err.is_err());
}

#[test]
fn romulus_n_wrong_tag_empty_message_fails() {
    let key = GenericArray::from([9u8; 16]);
    let nonce = GenericArray::from([10u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = vec![];
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf)
        .unwrap();
    let mut bad = tag;
    bad[15] ^= 1;
    let err = cipher.decrypt_in_place_detached(&nonce, b"", &mut buf, &bad);
    assert!(err.is_err());
}

#[test]
fn romulus_n_truncated_ciphertext_fails() {
    let key = GenericArray::from([6u8; 16]);
    let nonce = GenericArray::from([7u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = vec![0xABu8; 32];
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf)
        .unwrap();
    buf.truncate(16);
    let err = cipher.decrypt_in_place_detached(&nonce, b"", &mut buf, &tag);
    assert!(err.is_err());
    assert!(
        buf.iter().all(|&b| b == 0),
        "plaintext buffer cleared on failure"
    );
}

#[test]
fn romulus_m_wrong_tag_fails() {
    let key = GenericArray::from([11u8; 16]);
    let nonce = GenericArray::from([12u8; 16]);
    let cipher = RomulusM::new(&key);
    let mut buf = b"msg".to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"z", &mut buf)
        .unwrap();
    let mut bad = tag;
    bad[5] ^= 0x55;
    let err = cipher.decrypt_in_place_detached(&nonce, b"z", &mut buf, &bad);
    assert!(err.is_err());
}
