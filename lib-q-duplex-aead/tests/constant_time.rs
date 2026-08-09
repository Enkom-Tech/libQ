//! Structural (non-timing) pin on the AEAD tag comparison in `crypto.rs::decrypt` (`ct_eq`).
//!
//! Does NOT measure wall-clock timing -- that is unmeasurable in a unit test and out of scope
//! per card t_043571b4 (a prior "constant-time" test compared two algorithms' speeds and was
//! rejected). What these tests pin is the code shape: decryption must reject a tampered
//! ciphertext regardless of WHERE the corrupted byte sits (body or tag), and a truncated
//! ciphertext must be rejected outright rather than compared prefix-wise. A short-circuiting
//! tag comparison (the class of regression fixed at ed104c2 for seven `PartialEq` impls
//! elsewhere in this repo) would still fail every individual case below on OUTPUT alone if it
//! only inspected a prefix of the tag -- that is exactly what `tag_mismatch_rejected_at_every_position`
//! is built to catch.

use lib_q_core::{
    Aead,
    AeadKey,
    Nonce,
};
use lib_q_duplex_aead::DuplexSpongeAead;

fn setup() -> (DuplexSpongeAead, AeadKey, Nonce, Vec<u8>) {
    let aead = DuplexSpongeAead::new();
    let key = AeadKey::new(vec![0x11u8; 32]);
    let nonce = Nonce::new(vec![0x22u8; 16]);
    let pt = b"constant time pin message".to_vec();
    let ct = aead.encrypt(&key, &nonce, &pt, Some(b"ad")).unwrap();
    (aead, key, nonce, ct)
}

/// Flips every byte of the ciphertext (body and tag) at every position and confirms
/// decryption is rejected in all cases -- including a tag-only flip at the LAST byte of the
/// tag, which a truncated/prefix comparison could silently accept.
#[test]
fn tag_mismatch_rejected_at_every_position() {
    let (aead, key, nonce, ct) = setup();
    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(
            aead.decrypt(&key, &nonce, &bad, Some(b"ad")).is_err(),
            "corruption at byte {i} of {} was not rejected",
            ct.len()
        );
    }
}

/// First-byte-of-tag vs last-byte-of-tag corruption must both be rejected. Pins that neither
/// tag position is special-cased in the boolean outcome (does not establish equal timing).
#[test]
fn first_and_last_tag_byte_both_rejected() {
    let (aead, key, nonce, ct) = setup();
    let tag_start = ct.len() - 16; // TAG_BYTES = 16 for this duplex construction
    let mut bad_first = ct.clone();
    bad_first[tag_start] ^= 0xFF;
    let mut bad_last = ct.clone();
    let last = ct.len() - 1;
    bad_last[last] ^= 0xFF;

    assert!(aead.decrypt(&key, &nonce, &bad_first, Some(b"ad")).is_err());
    assert!(aead.decrypt(&key, &nonce, &bad_last, Some(b"ad")).is_err());
}

/// A truncated ciphertext (shorter than the tag) must be rejected outright, never compared
/// prefix-wise against a would-be truncated tag.
#[test]
fn truncated_ciphertext_rejected() {
    let (aead, key, nonce, ct) = setup();
    for len in 0..16 {
        let truncated = &ct[..len];
        assert!(aead.decrypt(&key, &nonce, truncated, Some(b"ad")).is_err());
    }
}
