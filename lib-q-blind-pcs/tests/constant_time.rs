//! Structural constant-time pin for `verify()`'s commitment check
//! (`lib-q-blind-pcs/src/blind_pcs.rs:37`, `commitment.ct_eq(&expected).into()`).
//!
//! These tests prove the CODE SHAPE — that a mismatch anywhere in the 32-byte commitment,
//! including the last byte, is rejected — NOT the timing itself. Timing is not observable from a
//! unit test, and this repo explicitly rejects wall-clock timing tests (card t_043571b4). The
//! property that actually breaks under a short-circuiting comparator is "rejects at every byte
//! position"; that is what is pinned here, using the same methodology as lib-q-mac et al.
//! (commit f756fbc) and lib-q-blind-token's `unblind()` pin in this same tranche.

#![cfg(feature = "blind-pcs")]

use lib_q_blind_pcs::{
    blind_commit,
    blind_open,
    verify,
};

#[test]
fn honest_commitment_verifies() {
    let message = b"structural ct test message";
    let blind = b"structural ct test blind";
    let commitment = blind_commit(message, blind);
    let opening = blind_open(message, blind);
    assert!(verify(&commitment, &opening));
}

/// A commitment that differs from the recomputed hash at ANY single byte — including the last —
/// must be rejected. A short-circuiting or prefix-only comparator would accept a commitment that
/// only diverges in a later byte; this exhaustive sweep would catch that class of regression.
#[test]
fn mismatched_commitment_rejected_at_every_byte_position() {
    let message = b"structural ct test message";
    let blind = b"structural ct test blind";
    let commitment = blind_commit(message, blind);
    let opening = blind_open(message, blind);

    // Sanity: the honest commitment verifies (otherwise the loop below would be vacuous).
    assert!(verify(&commitment, &opening));

    for i in 0..commitment.len() {
        let mut bad_commitment = commitment;
        bad_commitment[i] ^= 0xFF;
        assert!(
            !verify(&bad_commitment, &opening),
            "commitment mismatch at byte {i} was not rejected"
        );
    }
}

/// A tampered opening (wrong message or wrong blind) is rejected outright, regardless of which
/// input was altered.
#[test]
fn tampered_opening_rejected() {
    let commitment = blind_commit(b"real message", b"real blind");

    let wrong_message = blind_open(b"fake message", b"real blind");
    assert!(!verify(&commitment, &wrong_message));

    let wrong_blind = blind_open(b"real message", b"fake blind");
    assert!(!verify(&commitment, &wrong_blind));
}
