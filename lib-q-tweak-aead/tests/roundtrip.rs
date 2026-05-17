use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
};
use lib_q_tweak_aead::params::{
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
};
use lib_q_tweak_aead::{
    TweakAead,
    crypto,
};

#[test]
fn roundtrip_empty_ad() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![0xA5u8; 32]);
    let nonce = Nonce::new(vec![0x3Cu8; 16]);
    let pt = b"hello tweak aead";
    let ct = aead.encrypt(&key, &nonce, pt, None).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn roundtrip_with_ad() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![1u8; 32]);
    let nonce = Nonce::new(vec![2u8; 16]);
    let ad = b"associated";
    let pt = vec![0u8; 100];
    let ct = aead.encrypt(&key, &nonce, &pt, Some(ad)).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, Some(ad)).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn roundtrip_multi_block() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![9u8; 32]);
    let nonce = Nonce::new(vec![8u8; 16]);
    let pt = vec![0xEEu8; 128];
    let ct = aead.encrypt(&key, &nonce, &pt, None).unwrap();
    let dec = aead.decrypt(&key, &nonce, &ct, None).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn tamper_fails() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![5u8; 32]);
    let nonce = Nonce::new(vec![6u8; 16]);
    let mut ct = aead.encrypt(&key, &nonce, b"x", None).unwrap();
    ct[0] ^= 1;
    assert!(aead.decrypt(&key, &nonce, &ct, None).is_err());
}

#[test]
fn decrypt_failure_clears_output_buffer() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![5u8; 32]);
    let nonce = Nonce::new(vec![6u8; 16]);
    let mut ct = aead.encrypt(&key, &nonce, b"payload", None).unwrap();
    ct[0] ^= 1;

    let mut key_arr = [0u8; KEY_BYTES];
    key_arr.copy_from_slice(key.as_bytes());
    let mut nonce_arr = [0u8; NONCE_BYTES];
    nonce_arr.copy_from_slice(nonce.as_bytes());

    let body_len = ct.len() - TAG_BYTES;
    let mut out = vec![0xABu8; body_len];
    assert!(crypto::decrypt(&key_arr, &nonce_arr, &[], &ct, &mut out).is_err());
    assert!(
        out.iter().all(|&b| b == 0),
        "plaintext slice must be zeroed when tag verification fails"
    );
}

#[test]
fn tweak_aead_decrypt_semantic_success_matches_decrypt() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![0x11u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0x22u8; NONCE_BYTES]);
    let ad = b"associated";
    let pt = b"plaintext body";
    let ct = aead.encrypt(&key, &nonce, pt, Some(ad)).expect("encrypt");
    let layer_a = aead.decrypt(&key, &nonce, &ct, Some(ad)).expect("decrypt");
    match aead
        .decrypt_semantic(&key, &nonce, &ct, Some(ad))
        .expect("decrypt_semantic")
    {
        DecryptSemanticOutcome::Success(got) => assert_eq!(got.as_slice(), layer_a.as_slice()),
        DecryptSemanticOutcome::AuthenticationFailed => {
            panic!("expected Success for valid ciphertext")
        }
    }
}

#[test]
fn tweak_aead_decrypt_semantic_tampered_tag_is_authentication_failed() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![0x33u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0x44u8; NONCE_BYTES]);
    let pt = b"msg";
    let mut ct = aead.encrypt(&key, &nonce, pt, None).expect("encrypt");
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    let outcome = aead
        .decrypt_semantic(&key, &nonce, &ct, None)
        .expect("operational path ok");
    assert_eq!(outcome, DecryptSemanticOutcome::AuthenticationFailed);
}

#[test]
fn tweak_aead_decrypt_semantic_ciphertext_too_short_is_err() {
    let aead = TweakAead::new();
    let key = AeadKey::new(vec![0x55u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0x66u8; NONCE_BYTES]);
    let r = aead.decrypt_semantic(&key, &nonce, &[0u8; TAG_BYTES - 1], None);
    assert!(matches!(r, Err(Error::InvalidCiphertextSize { .. })));
}
