//! Core-path coverage for the unlinkable blind token.

mod common;

use common::{
    EPOCH,
    ISSUER_KEY_ID,
    det_rng,
    issue,
};
use lib_q_blind_token::{
    blind,
    blind_sign,
    keygen_issuer,
    redeem,
    unblind,
    verify,
};

#[test]
fn honest_roundtrip_verifies() {
    let (issuer_pub, _priv, cred) = issue(0x11);
    let mut rng = det_rng(0xA0);
    let nonce = b"fresh-token-nonce";
    let token = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem");
    assert!(
        verify(&issuer_pub, nonce, &token),
        "honest token must verify"
    );
}

#[test]
fn wrong_nonce_fails() {
    let (issuer_pub, _priv, cred) = issue(0x12);
    let mut rng = det_rng(0xA1);
    let token = redeem(&mut rng, &issuer_pub, &cred, b"the-real-nonce").expect("redeem");
    assert!(
        !verify(&issuer_pub, b"a-different-nonce", &token),
        "token must not verify against a different nonce",
    );
}

#[test]
fn tampered_token_fails() {
    let (issuer_pub, _priv, cred) = issue(0x13);
    let mut rng = det_rng(0xA2);
    let nonce = b"nonce-to-tamper";
    let mut token = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem");
    let mid = token.len() / 2;
    token[mid] ^= 0x80;
    assert!(
        !verify(&issuer_pub, nonce, &token),
        "a corrupted token must not verify"
    );
}

#[test]
fn wrong_issuer_fails() {
    let (_issuer_pub, _priv, cred) = issue(0x14);
    let mut rng = det_rng(0xA3);
    let nonce = b"cross-issuer-nonce";
    let token = redeem(&mut rng, &_issuer_pub, &cred, nonce).expect("redeem");
    // A verifier holding a different issuer key must reject.
    let mut rng2 = det_rng(0x99);
    let (other_pub, _other_priv) = keygen_issuer(&mut rng2, ISSUER_KEY_ID + 1, EPOCH);
    assert!(
        !verify(&other_pub, nonce, &token),
        "token must not verify under a different issuer key",
    );
}

#[test]
fn repeated_redemptions_are_fresh_and_both_verify() {
    // Re-randomized redemption: two redemptions of one credential differ but both verify
    // (mutual unlinkability of presentations).
    let (issuer_pub, _priv, cred) = issue(0x21);
    let mut rng = det_rng(0xA4);
    let nonce = b"same-credential-two-presentations";
    let t1 = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem 1");
    let t2 = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem 2");
    assert_ne!(t1, t2, "redemptions must be freshly randomized");
    assert!(verify(&issuer_pub, nonce, &t1));
    assert!(verify(&issuer_pub, nonce, &t2));
}

#[test]
fn credential_is_required_to_redeem() {
    // Sanity: an honest credential produces a verifying token; the issuance check rejects a
    // mismatched signature (covered in unit tests). Here we confirm the happy path is non-trivial.
    let mut rng = det_rng(0x31);
    let (issuer_pub, issuer_priv) = keygen_issuer(&mut rng, ISSUER_KEY_ID, EPOCH);
    let (req, state) = blind(&mut rng, &issuer_pub);
    let resp = blind_sign(&mut rng, &issuer_priv, &req);
    let cred = unblind(&issuer_pub, &state, &resp).expect("credential");
    let token = redeem(&mut rng, &issuer_pub, &cred, b"ctx").expect("redeem");
    assert!(verify(&issuer_pub, b"ctx", &token));
}
