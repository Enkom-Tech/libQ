//! Token codec round-trip.

mod common;

use common::{
    det_rng,
    issue,
};
use lib_q_blind_token::{
    decode_token_value,
    encode_token_value,
    redeem,
    verify,
};

#[test]
fn token_value_roundtrip_is_stable_and_verifies() {
    let (issuer_pub, _priv, cred) = issue(0x31);
    let mut rng = det_rng(0xB0);
    let nonce = b"roundtrip-nonce";
    let token = redeem(&mut rng, &issuer_pub, &cred, nonce).expect("redeem");

    // decode → re-encode must be byte-stable.
    let decoded = decode_token_value(&token).expect("decode");
    let reencoded = encode_token_value(&decoded).expect("encode");
    assert_eq!(token, reencoded, "token codec must round-trip");

    // and the round-tripped token still verifies.
    assert!(verify(&issuer_pub, nonce, &reencoded));
}
