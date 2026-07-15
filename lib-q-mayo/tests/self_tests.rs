#![cfg(feature = "mayo2")]

//! Roundtrip, wire-format, tamper-rejection, and redaction self tests.

use lib_q_mayo::{
    Mayo2Signature,
    Mayo2SigningKey,
    Mayo2VerificationKey,
    mayo_2,
};

#[test]
fn sizes() {
    assert_eq!(mayo_2::SIGNING_KEY_SIZE, 24);
    assert_eq!(mayo_2::VERIFICATION_KEY_SIZE, 4912);
    assert_eq!(mayo_2::SIGNATURE_SIZE, 186);
}

#[test]
fn roundtrip() {
    let kp = mayo_2::generate_key_pair([9u8; 24]);
    for (i, msg) in [b"".as_slice(), b"a", &[0u8; 1000]].iter().enumerate() {
        let sig = mayo_2::sign(&kp.signing_key, msg, [i as u8; 24]).unwrap();
        mayo_2::verify(&kp.verification_key, msg, &sig).unwrap();
    }
}

#[test]
fn deterministic_with_same_randomizer() {
    let kp = mayo_2::generate_key_pair([1u8; 24]);
    let a = mayo_2::sign(&kp.signing_key, b"msg", [7u8; 24]).unwrap();
    let b = mayo_2::sign(&kp.signing_key, b"msg", [7u8; 24]).unwrap();
    let c = mayo_2::sign(&kp.signing_key, b"msg", [8u8; 24]).unwrap();
    assert_eq!(a.as_slice(), b.as_slice());
    assert_ne!(a.as_slice(), c.as_slice());
    mayo_2::verify(&kp.verification_key, b"msg", &c).unwrap();
}

#[test]
fn rejects_wrong_message_key_and_tampered_sig() {
    let kp = mayo_2::generate_key_pair([2u8; 24]);
    let other = mayo_2::generate_key_pair([3u8; 24]);
    let sig = mayo_2::sign(&kp.signing_key, b"message", [0u8; 24]).unwrap();

    assert!(mayo_2::verify(&kp.verification_key, b"messagf", &sig).is_err());
    assert!(mayo_2::verify(&other.verification_key, b"message", &sig).is_err());

    for pos in [0, 100, 161, 162, 185] {
        let mut bad = sig.clone();
        bad.as_ref_mut()[pos] ^= 0x10;
        assert!(
            mayo_2::verify(&kp.verification_key, b"message", &bad).is_err(),
            "tamper at byte {pos} accepted"
        );
    }
}

#[test]
fn byte_exact_decode_rejects_wrong_lengths() {
    assert!(Mayo2SigningKey::try_from([0u8; 24].as_slice()).is_ok());
    assert!(Mayo2SigningKey::try_from([0u8; 23].as_slice()).is_err());
    assert!(Mayo2VerificationKey::try_from(vec![0u8; 4912].as_slice()).is_ok());
    assert!(Mayo2VerificationKey::try_from(vec![0u8; 4913].as_slice()).is_err());
    assert!(Mayo2Signature::try_from(vec![0u8; 186].as_slice()).is_ok());
    assert!(Mayo2Signature::try_from(vec![0u8; 185].as_slice()).is_err());
}

#[test]
fn signing_key_debug_is_redacted() {
    let kp = mayo_2::generate_key_pair([4u8; 24]);
    let dbg = format!("{:?}", kp.signing_key);
    assert!(dbg.contains("REDACTED"));
    // no key byte leaks as hex
    assert!(!dbg.contains("04040404"));
}
