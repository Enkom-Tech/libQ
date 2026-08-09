//! Structural (NOT wall-clock) constant-time test for Saturnin-SIV's tag comparison.
//!
//! # Why this test targets the comparator directly
//!
//! The house pattern (commit f756fbc) is an exhaustive by-position tamper test whose red demo is a
//! truncated comparator — swapping `ct_eq` for `expected[..8] == tag[..8]`, a plausible
//! short-circuit-shaped regression that a functionally-identical `ct_eq -> ==` swap would not
//! produce.
//!
//! For Saturnin-SIV that end-to-end red demo would be VACUOUS, and saying so is the point of this
//! comment. The keystream is derived from the entire tag, so ANY tampering — with the tag, the
//! body, the AD or the nonce — avalanches into the recovered plaintext and therefore changes
//! essentially every byte of the recomputed tag. A comparator that checked only the first 8 bytes
//! would still reject every mutation this test could construct (it would fail only with
//! probability 2^-64 per attempt), so the test would pass against the bug and prove nothing.
//!
//! So the exhaustive by-position test is applied to `ct_tag_eq` itself — the exact function
//! `SaturninSiv::open` authenticates with — where a truncated comparator does have an observable
//! failure. The end-to-end mutation coverage lives in `tests/saturnin_siv.rs`
//! (`every_single_bit_flip_in_the_ciphertext_is_rejected` and friends), whose red demo is a
//! skipped or misplaced verification rather than a truncated one.

#![cfg(feature = "saturnin-siv")]

use lib_q_aead::saturnin_siv::{
    SaturninSiv,
    TAG_BYTES,
    ct_tag_eq,
};

fn base_tag() -> [u8; TAG_BYTES] {
    let mut t = [0u8; TAG_BYTES];
    for (i, b) in t.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    t
}

#[test]
fn equal_tags_compare_equal() {
    let t = base_tag();
    assert!(
        bool::from(ct_tag_eq(&t, &t)),
        "a tag did not compare equal to itself"
    );
}

#[test]
fn a_mismatch_at_every_single_byte_position_is_rejected() {
    let t = base_tag();
    for i in 0..TAG_BYTES {
        let mut other = t;
        other[i] ^= 0xFF;
        assert!(
            !bool::from(ct_tag_eq(&t, &other)),
            "a tag differing only at byte {i} of {TAG_BYTES} compared equal — the comparator does \
             not look at that byte"
        );
    }
}

#[test]
fn a_single_bit_mismatch_at_every_position_is_rejected() {
    let t = base_tag();
    for i in 0..TAG_BYTES {
        for bit in 0..8u32 {
            let mut other = t;
            other[i] ^= 1u8 << bit;
            assert!(
                !bool::from(ct_tag_eq(&t, &other)),
                "a tag differing only in bit {bit} of byte {i} compared equal"
            );
        }
    }
}

#[test]
fn first_and_last_byte_mismatches_are_both_rejected() {
    let t = base_tag();

    let mut first = t;
    first[0] ^= 1;
    assert!(
        !bool::from(ct_tag_eq(&t, &first)),
        "a first-byte mismatch compared equal"
    );

    let mut last = t;
    last[TAG_BYTES - 1] ^= 1;
    assert!(
        !bool::from(ct_tag_eq(&t, &last)),
        "a last-byte mismatch compared equal — a prefix-only comparator would pass this"
    );
}

#[test]
fn the_comparator_open_uses_rejects_a_tag_that_matches_only_on_a_prefix() {
    // A tag identical to the real one on its first half and different on the second: the exact
    // shape a truncated comparator would wave through.
    let t = base_tag();
    let mut half = t;
    for b in half.iter_mut().skip(TAG_BYTES / 2) {
        *b ^= 0x5A;
    }
    assert_eq!(
        t[..TAG_BYTES / 2],
        half[..TAG_BYTES / 2],
        "test setup: the two tags must agree on the first half"
    );
    assert!(
        !bool::from(ct_tag_eq(&t, &half)),
        "a tag matching only on its first {} bytes was accepted",
        TAG_BYTES / 2
    );
}

#[test]
fn open_rejects_a_tag_that_matches_the_real_one_on_its_first_half() {
    // The end-to-end counterpart, kept honest about what it proves: it exercises `open`'s
    // authentication path with a prefix-shaped forgery attempt. It does NOT distinguish a
    // truncated comparator (see the module comment) — the per-position discrimination is the
    // `ct_tag_eq` tests above.
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 16];
    let siv = SaturninSiv::new();
    let ct = siv.seal(&key, &nonce, b"authentic", b"ad").expect("seal");

    let mut forged = ct.clone();
    for b in forged[TAG_BYTES / 2..TAG_BYTES].iter_mut() {
        *b ^= 0x5A;
    }
    assert_eq!(
        ct[..TAG_BYTES / 2],
        forged[..TAG_BYTES / 2],
        "test setup: the forged tag must agree with the real one on its first half"
    );
    assert!(
        siv.open(&key, &nonce, &forged, b"ad").is_err(),
        "a ciphertext whose tag matches only on its first half was accepted"
    );
}
