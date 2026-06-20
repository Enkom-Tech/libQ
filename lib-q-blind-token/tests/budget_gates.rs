//! Token byte budget gate.

mod common;

use common::{
    det_rng,
    issue,
};
use lib_q_blind_token::{
    BlindTokenError,
    WIRE_BUDGET_BLIND_TOKEN_BYTES,
    decode_token_value,
    redeem,
};

#[test]
fn token_within_budget() {
    let (issuer_pub, _priv, cred) = issue(0x41);
    let mut rng = det_rng(0xC0);
    let token = redeem(&mut rng, &issuer_pub, &cred, b"budget-nonce").expect("redeem");
    assert!(token.len() <= WIRE_BUDGET_BLIND_TOKEN_BYTES);
}

#[test]
fn oversized_token_rejected() {
    let oversized = vec![0u8; WIRE_BUDGET_BLIND_TOKEN_BYTES + 1];
    let err = decode_token_value(&oversized).expect_err("must reject");
    assert!(matches!(err, BlindTokenError::BudgetExceeded { .. }));
}
