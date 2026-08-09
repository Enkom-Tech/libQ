//! Structural (non-timing) pin on the tag comparison in `romulus_m.rs` / `romulus_n.rs`
//! (`bool::from(calc.ct_eq(tag))`).
//!
//! Does NOT measure wall-clock timing -- that is unmeasurable in a unit test and out of scope
//! per card t_043571b4 (a prior "constant-time" test compared two algorithms' speeds and was
//! rejected). What these tests pin is the code shape: verification must reject a forged tag
//! regardless of WHERE the tag diverges from the correct one -- including at the LAST byte,
//! which a short-circuiting or prefix-only comparison (the class of regression fixed at
//! ed104c2 for seven `PartialEq` impls elsewhere in this repo) would still accept. Romulus is
//! named explicitly in card t_f0d676d1 as a crate with a confirmed HIGH-severity finding and
//! no constant-time test at all -- this closes the latter for its tag-verify path (the S-box
//! table-lookup finding itself is tracked separately under t_7f110663).

use aead::array::Array;
use aead::{
    AeadInOut,
    KeyInit,
};
use lib_q_romulus::{
    RomulusM,
    RomulusN,
};

/// Flips every byte of a correct 16-byte tag independently and confirms verification is
/// rejected in all 16 cases -- including the last byte, which a prefix/short-circuit
/// comparison could accept while still failing on an early-byte flip.
#[test]
fn romulus_n_tag_mismatch_rejected_at_every_byte() {
    let key = Array::from([0x11u8; 16]);
    let nonce = Array::from([0x22u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"constant time pin message".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"ad", buf.as_mut_slice().into())
        .unwrap();

    for i in 0..tag.len() {
        let mut bad_tag = tag;
        bad_tag[i] ^= 0x01;
        let mut work = buf.clone();
        let err =
            cipher.decrypt_inout_detached(&nonce, b"ad", work.as_mut_slice().into(), &bad_tag);
        assert!(
            err.is_err(),
            "romulus-n: corruption at tag byte {i} of {} was not rejected",
            tag.len()
        );
    }
}

/// Same sweep for Romulus-M (the misuse-resistant / SIV-style mode) -- a separate `ct_eq` call
/// site in `romulus_m.rs`, so this is not redundant with the Romulus-N test above.
#[test]
fn romulus_m_tag_mismatch_rejected_at_every_byte() {
    let key = Array::from([0x33u8; 16]);
    let nonce = Array::from([0x44u8; 16]);
    let cipher = RomulusM::new(&key);
    let mut buf = b"constant time pin message".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"ad", buf.as_mut_slice().into())
        .unwrap();

    for i in 0..tag.len() {
        let mut bad_tag = tag;
        bad_tag[i] ^= 0x01;
        let mut work = buf.clone();
        let err =
            cipher.decrypt_inout_detached(&nonce, b"ad", work.as_mut_slice().into(), &bad_tag);
        assert!(
            err.is_err(),
            "romulus-m: corruption at tag byte {i} of {} was not rejected",
            tag.len()
        );
    }
}

/// First-byte-of-tag vs last-byte-of-tag corruption must both be rejected. A comparison that
/// only inspects a prefix (or stops at the first mismatching word) would reject the first case
/// but accept the second.
#[test]
fn romulus_n_first_and_last_tag_byte_both_rejected() {
    let key = Array::from([0x55u8; 16]);
    let nonce = Array::from([0x66u8; 16]);
    let cipher = RomulusN::new(&key);
    let mut buf = b"x".to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", buf.as_mut_slice().into())
        .unwrap();

    let mut bad_first = tag;
    bad_first[0] ^= 0xFF;
    let mut work1 = buf.clone();
    assert!(
        cipher
            .decrypt_inout_detached(&nonce, b"", work1.as_mut_slice().into(), &bad_first)
            .is_err()
    );

    let mut bad_last = tag;
    let last = bad_last.len() - 1;
    bad_last[last] ^= 0xFF;
    let mut work2 = buf.clone();
    assert!(
        cipher
            .decrypt_inout_detached(&nonce, b"", work2.as_mut_slice().into(), &bad_last)
            .is_err()
    );
}
