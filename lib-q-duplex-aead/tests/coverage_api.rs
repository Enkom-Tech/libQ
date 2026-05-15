//! Low-level error paths, `Debug` on [`DuplexCryptoError`], and allocating AEAD validation.

use lib_q_core::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Error,
    Nonce,
};
use lib_q_duplex_aead::crypto::{
    DuplexCryptoError,
    decrypt,
    encrypt,
};
use lib_q_duplex_aead::{
    DuplexSpongeAead,
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
};

#[test]
fn duplex_crypto_error_debug_non_empty() {
    let s = format!("{:?}", DuplexCryptoError);
    assert!(s.contains("DuplexCryptoError"), "{s}");
}

#[test]
fn duplex_encrypt_rejects_output_too_small() {
    let key = [0u8; KEY_BYTES];
    let nonce = [0u8; NONCE_BYTES];
    let mut out = [0u8; 4];
    assert!(encrypt(&key, &nonce, b"", b"hello", &mut out).is_err());
}

#[test]
fn duplex_sponge_aead_metadata_and_constructor() {
    let _a = DuplexSpongeAead::new();
    assert_eq!(DuplexSpongeAead::key_size(), KEY_BYTES);
    assert_eq!(DuplexSpongeAead::nonce_size(), NONCE_BYTES);
    assert_eq!(DuplexSpongeAead::tag_size(), TAG_BYTES);
}

#[test]
fn duplex_sponge_aead_invalid_key_length() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0u8; KEY_BYTES - 1]);
    let nonce = Nonce::new(vec![0u8; NONCE_BYTES]);
    let r = aead.encrypt(&key, &nonce, b"x", None);
    assert!(matches!(r, Err(Error::InvalidKeySize { .. })));
}

#[test]
fn duplex_sponge_aead_invalid_nonce_length() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0u8; NONCE_BYTES + 1]);
    let r = aead.encrypt(&key, &nonce, b"x", None);
    assert!(matches!(r, Err(Error::InvalidNonceSize { .. })));
}

#[test]
fn duplex_sponge_aead_decrypt_ciphertext_too_short_for_tag() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![7u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![8u8; NONCE_BYTES]);
    let r = aead.decrypt(&key, &nonce, &[0u8; TAG_BYTES - 1], None);
    assert!(matches!(r, Err(Error::InvalidCiphertextSize { .. })));
}

#[test]
fn duplex_decrypt_zeroes_output_on_tag_failure() {
    let key = [0x11u8; KEY_BYTES];
    let nonce = [0x22u8; NONCE_BYTES];
    let ad = b"ad";
    let pt = b"attack at dawn";
    let mut ct = vec![0u8; pt.len() + TAG_BYTES];
    encrypt(&key, &nonce, ad, pt, &mut ct).expect("encryption should succeed");
    ct[0] ^= 0x80;

    let mut out = vec![0xA5u8; pt.len()];
    let result = decrypt(&key, &nonce, ad, &ct, &mut out);
    assert!(result.is_err(), "tampered ciphertext must fail tag check");
    assert_eq!(
        out,
        vec![0u8; pt.len()],
        "decrypt must zero output on tag failure"
    );
}

#[test]
fn duplex_sponge_aead_decrypt_semantic_success_matches_decrypt() {
    let aead = DuplexSpongeAead::new();
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
fn duplex_sponge_aead_decrypt_semantic_tampered_tag_is_authentication_failed() {
    let aead = DuplexSpongeAead::new();
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
fn duplex_sponge_aead_decrypt_semantic_ciphertext_too_short_is_err() {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0x55u8; KEY_BYTES]);
    let nonce = Nonce::new(vec![0x66u8; NONCE_BYTES]);
    let r = aead.decrypt_semantic(&key, &nonce, &[0u8; TAG_BYTES - 1], None);
    assert!(matches!(r, Err(Error::InvalidCiphertextSize { .. })));
}
