//! Low-level error paths, `Debug` on [`DuplexCryptoError`], and allocating AEAD validation.

use lib_q_core::{
    Aead,
    AeadKey,
    Error,
    Nonce,
};
use lib_q_duplex_aead::crypto::{
    DuplexCryptoError,
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
    assert!(matches!(r, Err(Error::VerificationFailed { .. })));
}
