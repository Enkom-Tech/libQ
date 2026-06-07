//! Deterministic KAT vector replay.

mod common;

use common::kat_positive_cases;
use lib_q_mac::QcwMac;

#[test]
fn kat_vectors_verify() {
    for (name, msg, ad, tag) in kat_positive_cases() {
        assert!(
            QcwMac::verify(&common::kat_key(), &msg, &ad, &tag),
            "positive case {name} failed"
        );
    }
    let cases = kat_positive_cases();
    let (_, msg, ad, tag) = &cases[0];
    let mut tampered = tag.clone();
    tampered[0] ^= 0x01;
    assert!(!QcwMac::verify(&common::kat_key(), msg, ad, &tampered));
}
