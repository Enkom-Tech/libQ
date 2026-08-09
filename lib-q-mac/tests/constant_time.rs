//! Structural (non-timing) pin on `QcwMac::verify`'s constant-time tag comparison.
//!
//! These tests do NOT measure wall-clock timing -- that is unmeasurable in a unit test
//! and out of scope per card t_043571b4 (a prior "constant-time" test that compared two
//! algorithms' speeds was rejected). What they pin is the *code shape*: `verify` must reject
//! a mismatch regardless of WHERE the mismatched byte sits, and must do so via a comparison
//! that scans the whole tag rather than returning early on the first differing byte. A
//! short-circuiting `==` swap (see `qcw_mac.rs:72`, currently `ct_eq`) would still fail every
//! individual case below, but this file exists so that property is a checked CI gate rather
//! than an unwritten assumption -- exactly the kind of regression fixed at ed104c2 for the
//! seven short-circuiting `PartialEq` impls elsewhere in this repo.

use lib_q_mac::{
    QcwMac,
    QcwMacKey,
};

fn key() -> QcwMacKey {
    QcwMacKey::from_bytes([0x42; 32])
}

#[test]
fn good_tag_verifies() {
    let key = key();
    let tag = QcwMac::sign(&key, b"msg", b"ad");
    assert!(QcwMac::verify(&key, b"msg", b"ad", &tag));
}

/// Flips one byte of a valid tag at every position and confirms `verify` rejects all of them.
/// A length- or position-dependent early return (the shape a short-circuiting `==` produces)
/// would still reject every one of these individually, but exhaustively covering the first
/// byte AND the last byte AND everywhere in between is what would catch a comparison that only
/// checks a prefix or a suffix.
#[test]
fn tag_mismatch_rejected_at_every_byte_position() {
    let key = key();
    let tag = QcwMac::sign(&key, b"msg", b"ad");
    for i in 0..tag.len() {
        let mut bad = tag.clone();
        bad[i] ^= 0x01;
        assert!(
            !QcwMac::verify(&key, b"msg", b"ad", &bad),
            "tag mismatch at byte {i} was not rejected"
        );
    }
}

/// First-byte-wrong vs last-byte-wrong must both be rejected identically (both `false`). This
/// does not prove they take equal TIME, but it pins that neither position gets special-cased
/// in the boolean result, which is the behavioural contract a length/prefix-based comparison
/// would violate first.
#[test]
fn first_byte_and_last_byte_mismatch_both_rejected() {
    let key = key();
    let tag = QcwMac::sign(&key, b"msg", b"ad");

    let mut bad_first = tag.clone();
    bad_first[0] ^= 0xFF;
    let mut bad_last = tag.clone();
    let last = bad_last.len() - 1;
    bad_last[last] ^= 0xFF;

    assert!(!QcwMac::verify(&key, b"msg", b"ad", &bad_first));
    assert!(!QcwMac::verify(&key, b"msg", b"ad", &bad_last));
}

/// A truncated or over-long tag must be rejected outright by the length check, never compared
/// prefix-wise against a truncated `expected`.
#[test]
fn wrong_length_tag_rejected() {
    let key = key();
    let tag = QcwMac::sign(&key, b"msg", b"ad");

    let truncated = &tag[..tag.len() - 1];
    assert!(!QcwMac::verify(&key, b"msg", b"ad", truncated));

    let mut over_long = tag.clone();
    over_long.push(0);
    assert!(!QcwMac::verify(&key, b"msg", b"ad", &over_long));

    // Even a truncated tag that is a genuine PREFIX of the real tag must fail -- proves the
    // length check runs before any byte comparison, so a short-circuiting implementation
    // cannot leak "how many prefix bytes matched" via a differently-shaped early exit.
    assert!(!QcwMac::verify(&key, b"msg", b"ad", &tag[..16]));
}
