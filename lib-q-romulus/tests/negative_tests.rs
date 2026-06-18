//! Negative tests: wrong tag, nonce, AD, truncated ciphertext.

#![cfg(feature = "std")]

use aead::array::Array;
use aead::{
    AeadInOut,
    KeyInit,
};
use lib_q_romulus::{
    RomulusM,
    RomulusN,
};

#[test]
fn romulus_n_wrong_tag_fails() {
    let key = Array::from([7u8; 16]);
    let nonce = Array::from([8u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"hello romulus".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"ad", buf.as_mut_slice().into())
        .unwrap();
    let mut bad = tag;
    bad[0] ^= 0xFF;
    let err = cipher.decrypt_inout_detached(&nonce, b"ad", buf.as_mut_slice().into(), &bad);
    assert!(err.is_err());
    assert!(
        buf.iter().all(|&b| b == 0),
        "plaintext should be cleared on failure"
    );
}

#[test]
fn romulus_n_wrong_nonce_fails() {
    let key = Array::from([1u8; 16]);
    let n1 = Array::from([2u8; 16]);
    let n2 = Array::from([3u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"data".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&n1, b"", buf.as_mut_slice().into())
        .unwrap();
    let err = cipher.decrypt_inout_detached(&n2, b"", buf.as_mut_slice().into(), &tag);
    assert!(err.is_err());
}

#[test]
fn romulus_n_wrong_ad_fails() {
    let key = Array::from([4u8; 16]);
    let nonce = Array::from([5u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"x".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"ad1", buf.as_mut_slice().into())
        .unwrap();
    let err = cipher.decrypt_inout_detached(&nonce, b"ad2", buf.as_mut_slice().into(), &tag);
    assert!(err.is_err());
}

#[test]
fn romulus_n_wrong_tag_empty_message_fails() {
    let key = Array::from([9u8; 16]);
    let nonce = Array::from([10u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = vec![];
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
        .unwrap();
    let mut bad = tag;
    bad[15] ^= 1;
    let err = cipher.decrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into(), &bad);
    assert!(err.is_err());
}

#[test]
fn romulus_n_truncated_ciphertext_fails() {
    let key = Array::from([6u8; 16]);
    let nonce = Array::from([7u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = vec![0xABu8; 32];
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
        .unwrap();
    buf.truncate(16);
    let err = cipher.decrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into(), &tag);
    assert!(err.is_err());
    assert!(
        buf.iter().all(|&b| b == 0),
        "plaintext buffer cleared on failure"
    );
}

#[test]
fn romulus_m_wrong_tag_fails() {
    let key = Array::from([11u8; 16]);
    let nonce = Array::from([12u8; 16]);
    let cipher = RomulusM::new(&key);
    let mut buf = b"msg".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"z", buf.as_mut_slice().into())
        .unwrap();
    let mut bad = tag;
    bad[5] ^= 0x55;
    let err = cipher.decrypt_inout_detached(&nonce, b"z", buf.as_mut_slice().into(), &bad);
    assert!(err.is_err());
}
