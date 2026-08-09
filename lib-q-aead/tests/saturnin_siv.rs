//! Saturnin-SIV: round-trip, tamper detection, and the nonce-reuse property that is the whole
//! point of the mode.
//!
//! Every test here fails for a specific, named reason; none of them is a smoke test.

#![cfg(feature = "saturnin-siv")]

use lib_q_aead::saturnin_siv::{
    SaturninSiv,
    TAG_BYTES,
};
use lib_q_aead::{
    Aead,
    AeadKey,
    Nonce,
};

const KEY: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
];
const NONCE: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];
const AD: &[u8] = b"associated-data";

fn siv() -> SaturninSiv {
    SaturninSiv::new()
}

#[test]
fn round_trip_over_lengths_that_straddle_the_32_byte_block() {
    // 0 forces the empty-plaintext path; 31/32/33 straddle the Saturnin block; 200 spans blocks.
    for len in [0usize, 1, 31, 32, 33, 63, 64, 200] {
        let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
        let ct = siv().seal(&KEY, &NONCE, &pt, AD).expect("seal");

        assert_eq!(
            ct.len(),
            TAG_BYTES + len,
            "ciphertext for a {len}-byte plaintext should be tag+len"
        );

        let got = siv().open(&KEY, &NONCE, &ct, AD).expect("open");
        assert_eq!(got, pt, "round-trip failed at length {len}");
    }
}

#[test]
fn round_trip_with_empty_ad_and_empty_nonce() {
    let ct = siv().seal(&KEY, &[], b"payload", &[]).expect("seal");
    let got = siv().open(&KEY, &[], &ct, &[]).expect("open");
    assert_eq!(got, b"payload");
}

// ---------------------------------------------------------------------------------------------
// Determinism — the defining SIV property, and what makes the nonce-reuse test below non-vacuous
// ---------------------------------------------------------------------------------------------

#[test]
fn same_key_nonce_ad_plaintext_gives_byte_identical_ciphertext() {
    let a = siv().seal(&KEY, &NONCE, b"identical input", AD).expect("a");
    let b = siv().seal(&KEY, &NONCE, b"identical input", AD).expect("b");
    assert_eq!(
        a, b,
        "Saturnin-SIV must be deterministic; a differing second encryption means the keystream \
         or tag is drawing on something outside (key, nonce, AD, plaintext)"
    );
}

#[test]
fn changing_only_the_ad_changes_the_whole_ciphertext_not_just_the_tag() {
    let a = siv()
        .seal(&KEY, &NONCE, b"same plaintext", b"ad-1")
        .expect("a");
    let b = siv()
        .seal(&KEY, &NONCE, b"same plaintext", b"ad-2")
        .expect("b");

    assert_ne!(a[..TAG_BYTES], b[..TAG_BYTES], "tag ignored the AD");
    assert_ne!(
        a[TAG_BYTES..],
        b[TAG_BYTES..],
        "ciphertext body ignored the AD: the keystream is not derived from the tag, so the SIV \
         property does not hold"
    );
}

// ---------------------------------------------------------------------------------------------
// NONCE REUSE — the gap this mode exists to close
// ---------------------------------------------------------------------------------------------

#[test]
fn nonce_reuse_two_different_plaintexts_both_decrypt_and_keystreams_do_not_collide() {
    let p1 = vec![0xAAu8; 64];
    let p2 = vec![0xBBu8; 64];

    let c1 = siv().seal(&KEY, &NONCE, &p1, AD).expect("c1");
    let c2 = siv().seal(&KEY, &NONCE, &p2, AD).expect("c2");

    // Both still decrypt correctly under the repeated nonce.
    assert_eq!(siv().open(&KEY, &NONCE, &c1, AD).expect("open c1"), p1);
    assert_eq!(siv().open(&KEY, &NONCE, &c2, AD).expect("open c2"), p2);

    // The catastrophic CTR nonce-reuse failure is a SHARED keystream: with it,
    // c1 XOR c2 == p1 XOR p2 and both plaintexts fall out. Show that does not happen.
    let x: Vec<u8> = c1[TAG_BYTES..]
        .iter()
        .zip(&c2[TAG_BYTES..])
        .map(|(a, b)| a ^ b)
        .collect();
    let p: Vec<u8> = p1.iter().zip(&p2).map(|(a, b)| a ^ b).collect();
    assert_ne!(
        x, p,
        "ciphertexts XOR to the plaintext XOR: the two messages shared a keystream, which is \
         exactly the nonce-reuse catastrophe this mode is supposed to prevent"
    );
}

#[test]
fn nonce_reuse_does_not_let_a_ciphertext_from_one_message_forge_another() {
    let p1 = b"transfer 10 to alice";
    let p2 = b"transfer 99 to mallo";
    assert_eq!(p1.len(), p2.len(), "test needs equal-length messages");

    let c1 = siv().seal(&KEY, &NONCE, p1, AD).expect("c1");
    let c2 = siv().seal(&KEY, &NONCE, p2, AD).expect("c2");

    // Splice: keep message 1's tag, attach message 2's body (the classic cut-and-paste under a
    // repeated nonce). Under a shared keystream this would decrypt to a valid, attacker-chosen
    // message; here it must be rejected.
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&c1[..TAG_BYTES]);
    spliced.extend_from_slice(&c2[TAG_BYTES..]);
    assert!(
        siv().open(&KEY, &NONCE, &spliced, AD).is_err(),
        "a tag from one message accepted a body from another under a reused nonce"
    );

    // ...and the mirror splice.
    let mut spliced2 = Vec::new();
    spliced2.extend_from_slice(&c2[..TAG_BYTES]);
    spliced2.extend_from_slice(&c1[TAG_BYTES..]);
    assert!(
        siv().open(&KEY, &NONCE, &spliced2, AD).is_err(),
        "mirror splice accepted under a reused nonce"
    );
}

// ---------------------------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------------------------

#[test]
fn every_single_bit_flip_in_the_ciphertext_is_rejected() {
    let pt = b"tamper me if you can";
    let ct = siv().seal(&KEY, &NONCE, pt, AD).expect("seal");

    for byte in 0..ct.len() {
        for bit in 0..8u32 {
            let mut bad = ct.clone();
            bad[byte] ^= 1u8 << bit;
            assert!(
                siv().open(&KEY, &NONCE, &bad, AD).is_err(),
                "flipping bit {bit} of byte {byte} (of {}) was accepted",
                ct.len()
            );
        }
    }
}

#[test]
fn truncated_and_extended_ciphertexts_are_rejected() {
    let ct = siv().seal(&KEY, &NONCE, b"0123456789", AD).expect("seal");

    for cut in 1..=ct.len() {
        let bad = &ct[..ct.len() - cut];
        assert!(
            siv().open(&KEY, &NONCE, bad, AD).is_err(),
            "ciphertext truncated by {cut} byte(s) was accepted"
        );
    }

    let mut extended = ct.clone();
    extended.push(0);
    assert!(
        siv().open(&KEY, &NONCE, &extended, AD).is_err(),
        "ciphertext with an appended byte was accepted"
    );
}

#[test]
fn a_changed_ad_is_rejected() {
    let ct = siv().seal(&KEY, &NONCE, b"payload", AD).expect("seal");

    assert!(
        siv().open(&KEY, &NONCE, &ct, b"associated-datA").is_err(),
        "a one-byte change in the AD was accepted"
    );
    assert!(
        siv().open(&KEY, &NONCE, &ct, &[]).is_err(),
        "dropping the AD entirely was accepted"
    );

    let mut longer = AD.to_vec();
    longer.push(0);
    assert!(
        siv().open(&KEY, &NONCE, &ct, &longer).is_err(),
        "appending a zero byte to the AD was accepted (length is not authenticated)"
    );
}

#[test]
fn a_changed_nonce_is_rejected() {
    let ct = siv().seal(&KEY, &NONCE, b"payload", AD).expect("seal");

    for i in 0..NONCE.len() {
        let mut n = NONCE;
        n[i] ^= 0x80;
        assert!(
            siv().open(&KEY, &n, &ct, AD).is_err(),
            "a flipped bit in nonce byte {i} was accepted"
        );
    }

    assert!(
        siv().open(&KEY, &[], &ct, AD).is_err(),
        "an empty nonce was accepted for a ciphertext sealed under a 16-byte nonce"
    );
}

#[test]
fn a_wrong_key_is_rejected() {
    let ct = siv().seal(&KEY, &NONCE, b"payload", AD).expect("seal");

    for i in 0..KEY.len() {
        let mut k = KEY;
        k[i] ^= 1;
        assert!(
            siv().open(&k, &NONCE, &ct, AD).is_err(),
            "a one-bit-different key at byte {i} decrypted the ciphertext"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------------------------

#[test]
fn wrong_key_length_is_an_error_not_a_panic() {
    for len in [0usize, 16, 31, 33, 64] {
        let k = vec![0u8; len];
        assert!(
            siv().seal(&k, &NONCE, b"x", AD).is_err(),
            "a {len}-byte key was accepted for seal"
        );
        assert!(
            siv().open(&k, &NONCE, &[0u8; 48], AD).is_err(),
            "a {len}-byte key was accepted for open"
        );
    }
}

#[test]
fn an_over_long_nonce_is_rejected() {
    let n = vec![0u8; 65];
    assert!(
        siv().seal(&KEY, &n, b"x", AD).is_err(),
        "a 65-byte nonce was accepted (MAX_NONCE_BYTES is 64)"
    );
    // 64 is the boundary and must still work.
    let n64 = vec![0u8; 64];
    let ct = siv().seal(&KEY, &n64, b"x", AD).expect("64-byte nonce");
    assert_eq!(siv().open(&KEY, &n64, &ct, AD).expect("open"), b"x");
}

#[test]
fn a_ciphertext_shorter_than_the_tag_is_rejected_without_panicking() {
    for len in 0..TAG_BYTES {
        let short = vec![0u8; len];
        assert!(
            siv().open(&KEY, &NONCE, &short, AD).is_err(),
            "a {len}-byte ciphertext (tag is {TAG_BYTES}) was accepted"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Trait surface
// ---------------------------------------------------------------------------------------------

#[test]
fn the_aead_trait_impl_agrees_with_the_inherent_api() {
    let key = AeadKey::new(KEY.to_vec());
    let nonce = Nonce::new(NONCE.to_vec());

    let via_trait = siv()
        .encrypt(&key, &nonce, b"trait path", Some(AD))
        .expect("encrypt");
    let via_inherent = siv().seal(&KEY, &NONCE, b"trait path", AD).expect("seal");
    assert_eq!(
        via_trait, via_inherent,
        "the Aead trait impl and seal() produced different ciphertexts"
    );

    let back = siv()
        .decrypt(&key, &nonce, &via_trait, Some(AD))
        .expect("decrypt");
    assert_eq!(back, b"trait path");

    // `None` associated data must mean the empty AD, not something else.
    let no_ad = siv()
        .encrypt(&key, &nonce, b"trait path", None)
        .expect("encrypt");
    assert_eq!(
        no_ad,
        siv().seal(&KEY, &NONCE, b"trait path", &[]).expect("seal"),
        "Aead::encrypt with None AD differs from seal() with an empty AD"
    );
}
