//! Integration tests for the Rocca-S AEAD public API.

use lib_q_rocca_s::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
    RoccaSAead,
};

fn aead() -> RoccaSAead {
    RoccaSAead::new()
}

fn key() -> AeadKey {
    AeadKey::new(vec![0x33; 32])
}

fn nonce() -> Nonce {
    Nonce::new(vec![0x77; 16])
}

#[test]
fn round_trip_various_lengths() {
    let a = aead();
    for len in [0usize, 1, 15, 16, 31, 32, 33, 63, 64, 100, 255, 1024] {
        let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let ad: Vec<u8> = (0..len % 17).map(|i| (i as u8) ^ 0xA5).collect();
        let ct = a.encrypt(&key(), &nonce(), &pt, Some(&ad)).unwrap();
        assert_eq!(ct.len(), pt.len() + 32);
        let back = a.decrypt(&key(), &nonce(), &ct, Some(&ad)).unwrap();
        assert_eq!(back, pt, "len {len}");
    }
}

#[test]
fn empty_message_and_ad() {
    let a = aead();
    let ct = a.encrypt(&key(), &nonce(), b"", None).unwrap();
    assert_eq!(ct.len(), 32);
    assert_eq!(a.decrypt(&key(), &nonce(), &ct, None).unwrap(), b"");
}

#[test]
fn wrong_ad_fails() {
    let a = aead();
    let ct = a.encrypt(&key(), &nonce(), b"data", Some(b"ad1")).unwrap();
    assert!(matches!(
        a.decrypt(&key(), &nonce(), &ct, Some(b"ad2")),
        Err(Error::VerificationFailed { .. })
    ));
}

#[test]
fn tampered_ciphertext_and_tag_fail() {
    let a = aead();
    let ct = a
        .encrypt(&key(), &nonce(), b"important payload", Some(b"hdr"))
        .unwrap();
    for idx in [0usize, 5, ct.len() - 1] {
        let mut bad = ct.clone();
        bad[idx] ^= 0x01;
        assert!(
            a.decrypt(&key(), &nonce(), &bad, Some(b"hdr")).is_err(),
            "flip at {idx} should fail"
        );
    }
}

#[test]
fn wrong_key_or_nonce_fails_auth() {
    let a = aead();
    let ct = a.encrypt(&key(), &nonce(), b"msg", Some(b"ad")).unwrap();
    let bad_key = AeadKey::new(vec![0x34; 32]);
    let bad_nonce = Nonce::new(vec![0x78; 16]);
    assert!(a.decrypt(&bad_key, &nonce(), &ct, Some(b"ad")).is_err());
    assert!(a.decrypt(&key(), &bad_nonce, &ct, Some(b"ad")).is_err());
}

#[test]
fn invalid_sizes_rejected() {
    let a = aead();
    let short_key = AeadKey::new(vec![0; 31]);
    let short_nonce = Nonce::new(vec![0; 15]);
    assert!(matches!(
        a.encrypt(&short_key, &nonce(), b"x", None),
        Err(Error::InvalidKeySize {
            expected: 32,
            actual: 31
        })
    ));
    assert!(matches!(
        a.encrypt(&key(), &short_nonce, b"x", None),
        Err(Error::InvalidNonceSize {
            expected: 16,
            actual: 15
        })
    ));
}

#[test]
fn ciphertext_shorter_than_tag_rejected() {
    let a = aead();
    let res = a.decrypt(&key(), &nonce(), &[0u8; 16], None);
    assert!(res.is_err());
}

#[test]
fn decrypt_semantic_outcomes() {
    let a = aead();
    let ct = a
        .encrypt(&key(), &nonce(), b"semantic", Some(b"ad"))
        .unwrap();
    match a
        .decrypt_semantic(&key(), &nonce(), &ct, Some(b"ad"))
        .unwrap()
    {
        DecryptSemanticOutcome::Success(p) => assert_eq!(p.as_slice(), b"semantic"),
        DecryptSemanticOutcome::AuthenticationFailed => panic!("unexpected auth failure"),
    }
    let mut bad = ct.clone();
    *bad.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        a.decrypt_semantic(&key(), &nonce(), &bad, Some(b"ad"))
            .unwrap(),
        DecryptSemanticOutcome::AuthenticationFailed
    );
}
