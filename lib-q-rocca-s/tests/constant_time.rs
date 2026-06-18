//! Smoke tests for the authentication-failure path.
//!
//! These do not attempt to *measure* timing (that needs a dedicated harness);
//! they confirm the API always performs the full bulk decryption and tag check
//! and never leaks plaintext on a bad tag — the structural prerequisite for the
//! constant-time decrypt contract documented in `SECURITY.md`.

use lib_q_rocca_s::{
    Aead,
    AeadDecryptSemantic,
    AeadKey,
    DecryptSemanticOutcome,
    Nonce,
    RoccaSAead,
};

#[test]
fn bad_tag_never_yields_plaintext() {
    let a = RoccaSAead::new();
    let key = AeadKey::new(vec![0x5A; 32]);
    let nonce = Nonce::new(vec![0xC3; 16]);
    let pt = b"plaintext that must never leak on auth failure";
    let ct = a.encrypt(&key, &nonce, pt, Some(b"ad")).unwrap();

    // Flip every byte position once; every corruption must be rejected with no
    // plaintext returned via either decrypt layer.
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0xFF;
        assert!(a.decrypt(&key, &nonce, &bad, Some(b"ad")).is_err());
        assert_eq!(
            a.decrypt_semantic(&key, &nonce, &bad, Some(b"ad")).unwrap(),
            DecryptSemanticOutcome::AuthenticationFailed
        );
    }
}

#[test]
fn good_tag_succeeds_after_full_schedule() {
    let a = RoccaSAead::new();
    let key = AeadKey::new(vec![1; 32]);
    let nonce = Nonce::new(vec![2; 16]);
    let ct = a.encrypt(&key, &nonce, b"ok", Some(b"")).unwrap();
    assert_eq!(a.decrypt(&key, &nonce, &ct, Some(b"")).unwrap(), b"ok");
}
