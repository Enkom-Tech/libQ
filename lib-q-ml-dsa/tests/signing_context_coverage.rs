//! Coverage for signing context length checks (FIPS 204 context ≤255 bytes).

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::types::{
    SigningError,
    VerificationError,
};
use lib_q_ml_dsa::{
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
};

/// FIPS 204 maximum context string length (bytes).
const CTX_MAX: usize = 255;

fn kg_seed(b: u8) -> [u8; KEY_GENERATION_RANDOMNESS_SIZE] {
    let mut s = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    s[0] = b;
    s
}

fn sig_seed(b: u8) -> [u8; SIGNING_RANDOMNESS_SIZE] {
    let mut s = [0u8; SIGNING_RANDOMNESS_SIZE];
    s[0] = b;
    s
}

#[test]
fn context_max_len_signs_for_all_parameter_sets() {
    let ctx = vec![0xA5u8; CTX_MAX];
    let kp44 = ml_dsa_44::generate_key_pair(kg_seed(1));
    assert!(ml_dsa_44::sign(&kp44.signing_key, b"m", &ctx, sig_seed(1)).is_ok());
    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(2));
    assert!(ml_dsa_65::sign(&kp65.signing_key, b"m", &ctx, sig_seed(2)).is_ok());
    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(3));
    assert!(ml_dsa_87::sign(&kp87.signing_key, b"m", &ctx, sig_seed(3)).is_ok());
}

#[test]
fn context_one_byte_over_max_fails_for_all_parameter_sets() {
    let ctx = vec![0x5Au8; CTX_MAX + 1];
    let kp44 = ml_dsa_44::generate_key_pair(kg_seed(4));
    assert!(matches!(
        ml_dsa_44::sign(&kp44.signing_key, b"m", &ctx, sig_seed(4)),
        Err(SigningError::ContextTooLongError)
    ));
    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(5));
    assert!(matches!(
        ml_dsa_65::sign(&kp65.signing_key, b"m", &ctx, sig_seed(5)),
        Err(SigningError::ContextTooLongError)
    ));
    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(6));
    assert!(matches!(
        ml_dsa_87::sign(&kp87.signing_key, b"m", &ctx, sig_seed(6)),
        Err(SigningError::ContextTooLongError)
    ));
}

#[test]
fn pre_hashed_sign_rejects_context_too_long() {
    let ctx = vec![0x3Cu8; CTX_MAX + 1];
    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(7));
    assert!(matches!(
        ml_dsa_65::sign_pre_hashed_shake128(&kp65.signing_key, b"m", &ctx, sig_seed(7),),
        Err(SigningError::ContextTooLongError)
    ));
}

#[test]
fn pre_hashed_verify_rejects_context_too_long() {
    let kp = ml_dsa_65::generate_key_pair(kg_seed(8));
    let sig = ml_dsa_65::sign_pre_hashed_shake128(&kp.signing_key, b"msgv", b"good", sig_seed(8))
        .expect("sign");
    let bad_ctx = vec![0xEEu8; CTX_MAX + 1];
    assert!(matches!(
        ml_dsa_65::verify_pre_hashed_shake128(&kp.verification_key, b"msgv", &bad_ctx, &sig),
        Err(VerificationError::VerificationContextTooLongError)
    ));
}

#[test]
fn pre_hashed_verify_context_too_long_44_and_87() {
    let bad = vec![1u8; CTX_MAX + 1];

    let kp44 = ml_dsa_44::generate_key_pair(kg_seed(9));
    let sig44 = ml_dsa_44::sign_pre_hashed_shake128(&kp44.signing_key, b"x", b"ok", sig_seed(9))
        .expect("s44");
    assert!(matches!(
        ml_dsa_44::verify_pre_hashed_shake128(&kp44.verification_key, b"x", &bad, &sig44),
        Err(VerificationError::VerificationContextTooLongError)
    ));

    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(10));
    let sig87 = ml_dsa_87::sign_pre_hashed_shake128(&kp87.signing_key, b"x", b"ok", sig_seed(10))
        .expect("s87");
    assert!(matches!(
        ml_dsa_87::verify_pre_hashed_shake128(&kp87.verification_key, b"x", &bad, &sig87),
        Err(VerificationError::VerificationContextTooLongError)
    ));
}
