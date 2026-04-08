//! Integration coverage for portable verify paths that return `Err` (wrong message, tampered bytes).

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_44::{
    self,
    MLDSA44Signature,
};
use lib_q_ml_dsa::ml_dsa_65::{
    self,
    MLDSA65Signature,
};
use lib_q_ml_dsa::ml_dsa_87::{
    self,
    MLDSA87Signature,
};

fn kg_seed(b: u8) -> [u8; KEY_GENERATION_RANDOMNESS_SIZE] {
    let mut s = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    s[0] = b;
    s[31] = b.wrapping_mul(11);
    s
}

fn sig_seed(b: u8) -> [u8; SIGNING_RANDOMNESS_SIZE] {
    let mut s = [0u8; SIGNING_RANDOMNESS_SIZE];
    s[0] = b;
    s[31] = b.wrapping_add(19);
    s
}

#[test]
fn standard_verify_fails_on_wrong_message_all_parameter_sets() {
    let kp44 = ml_dsa_44::generate_key_pair(kg_seed(0x10));
    let sig44 = ml_dsa_44::sign(&kp44.signing_key, b"alice", b"", sig_seed(0x20)).expect("sign 44");
    assert!(ml_dsa_44::verify(&kp44.verification_key, b"bob", b"", &sig44).is_err());

    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(0x11));
    let sig65 = ml_dsa_65::sign(&kp65.signing_key, b"alice", b"", sig_seed(0x21)).expect("sign 65");
    assert!(ml_dsa_65::verify(&kp65.verification_key, b"bob", b"", &sig65).is_err());

    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(0x12));
    let sig87 = ml_dsa_87::sign(&kp87.signing_key, b"alice", b"", sig_seed(0x22)).expect("sign 87");
    assert!(ml_dsa_87::verify(&kp87.verification_key, b"bob", b"", &sig87).is_err());
}

#[test]
fn prehash_verify_fails_on_wrong_message_all_parameter_sets() {
    let kp44 = ml_dsa_44::generate_key_pair(kg_seed(0x30));
    let sig44 =
        ml_dsa_44::sign_pre_hashed_shake128(&kp44.signing_key, b"payload", b"ctx", sig_seed(0x40))
            .expect("sign ph 44");
    assert!(
        ml_dsa_44::verify_pre_hashed_shake128(&kp44.verification_key, b"other", b"ctx", &sig44)
            .is_err()
    );

    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(0x31));
    let sig65 =
        ml_dsa_65::sign_pre_hashed_shake128(&kp65.signing_key, b"payload", b"ctx", sig_seed(0x41))
            .expect("sign ph 65");
    assert!(
        ml_dsa_65::verify_pre_hashed_shake128(&kp65.verification_key, b"other", b"ctx", &sig65)
            .is_err()
    );

    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(0x32));
    let sig87 =
        ml_dsa_87::sign_pre_hashed_shake128(&kp87.signing_key, b"payload", b"ctx", sig_seed(0x42))
            .expect("sign ph 87");
    assert!(
        ml_dsa_87::verify_pre_hashed_shake128(&kp87.verification_key, b"other", b"ctx", &sig87)
            .is_err()
    );
}

#[test]
fn tampered_signature_bytes_fail_verify_44() {
    let kp = ml_dsa_44::generate_key_pair(kg_seed(0x50));
    let good = ml_dsa_44::sign(&kp.signing_key, b"m", b"", sig_seed(0x60)).expect("sign");
    let template = *good.as_ref();
    for off in [0usize, 1, 17, template.len() / 3, template.len() - 1] {
        let mut bytes = template;
        bytes[off] ^= 0xA7;
        let bad = MLDSA44Signature::new(bytes);
        assert!(ml_dsa_44::verify(&kp.verification_key, b"m", b"", &bad).is_err());
    }
}

#[test]
fn tampered_signature_bytes_fail_verify_65_and_87() {
    let kp65 = ml_dsa_65::generate_key_pair(kg_seed(0x51));
    let good65 = ml_dsa_65::sign(&kp65.signing_key, b"m", b"", sig_seed(0x61)).expect("sign");
    let mut b65 = *good65.as_ref();
    b65[b65.len() / 2] ^= 1;
    assert!(
        ml_dsa_65::verify(
            &kp65.verification_key,
            b"m",
            b"",
            &MLDSA65Signature::new(b65)
        )
        .is_err()
    );

    let kp87 = ml_dsa_87::generate_key_pair(kg_seed(0x52));
    let good87 = ml_dsa_87::sign(&kp87.signing_key, b"m", b"", sig_seed(0x62)).expect("sign");
    let mut b87 = *good87.as_ref();
    b87[42] ^= 0x55;
    assert!(
        ml_dsa_87::verify(
            &kp87.verification_key,
            b"m",
            b"",
            &MLDSA87Signature::new(b87)
        )
        .is_err()
    );
}
