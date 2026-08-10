//! Structural constant-time coverage for the round-2 commitment-opening check.
//!
//! `aggregate_commitment` verifies each round-2 opening against the round-1 commitment that was
//! broadcast for it. That comparison used a short-circuiting `!=` on the 32-byte hash. An attacker
//! trying to open an honest party's commitment with a value they never committed to is comparing
//! against a target they do not control, so the number of leading bytes that matched is exactly
//! the byte-at-a-time forgery oracle: it reduces searching for a colliding opening from about
//! 2^256 work to about 32*256 probes. It now folds all 32 bytes with `subtle::ConstantTimeEq`.
//!
//! Being clear about what this file does and does not establish, because the distinction has bitten
//! this repo before. The fix is STRUCTURAL: the branch is gone by construction, and the evidence
//! for that is the shape of the code. A unit test cannot observe that two operands did equal work;
//! that needs dudect-style measurement, which is out of scope here.
//!
//! What these tests DO pin is the property that is testable and the realistic regression: that no
//! byte of the commitment is ignored. A comparison that silently checked only a prefix (or only
//! the first word) would still reject a wholly different commitment, so a single negative case
//! would not catch it. Every byte position is therefore exercised individually.

use lib_q_threshold_raccoon::threshold::{
    Round1Commit,
    aggregate_commitment,
    sign_round1,
    sign_round1_reveal,
};

/// Deterministic RNG so a failure names a reproducible case rather than a random one.
/// Matches the helper style already used in sign_verify.rs.
fn det(seed: u8) -> lib_q_random::LibQRng {
    lib_q_random::new_deterministic_rng([seed; 32])
}

fn one_party() -> (
    Round1Commit,
    lib_q_threshold_raccoon::threshold::Round1Reveal,
) {
    let mut r = det(0x5A);
    let (state, commit) = sign_round1(1, &mut r);
    let reveal = sign_round1_reveal(&state);
    (commit, reveal)
}

/// Baseline: a genuine opening must be accepted. Without this the rejection tests below could all
/// pass because aggregation rejects everything.
#[test]
fn genuine_opening_is_accepted() {
    let (commit, reveal) = one_party();
    assert!(
        aggregate_commitment(&[commit], &[reveal]).is_ok(),
        "a genuine round-2 opening must verify against its own round-1 commitment; if this fails, \
         every rejection assertion in this file is vacuous"
    );
}

/// Flipping any single byte of the commitment must be rejected.
///
/// Exhaustive over all 32 byte positions. This is the regression that matters: a comparison that
/// examined only the first N bytes would pass a test that tampers just one byte near the front,
/// and would silently accept forged openings differing only in the tail.
#[test]
fn rejects_a_commitment_altered_at_every_byte_position() {
    let (commit, reveal) = one_party();

    let mut checked = 0usize;
    for byte_index in 0..32usize {
        let mut tampered = commit.clone();
        tampered.com[byte_index] ^= 0xFF;

        assert!(
            aggregate_commitment(&[tampered], std::slice::from_ref(&reveal)).is_err(),
            "altering byte {byte_index} of the round-1 commitment was still accepted, so that \
             byte is not being compared"
        );
        checked += 1;
    }

    assert_eq!(
        checked, 32,
        "expected to cover all 32 commitment bytes; a shrunken range would test less while \
         still reporting ok"
    );
}

/// The same, one bit at a time rather than a whole byte, so a comparison that comes to depend on
/// a byte being wholly different (rather than merely unequal) is caught too.
#[test]
fn rejects_a_commitment_altered_at_every_single_bit() {
    let (commit, reveal) = one_party();

    let mut checked = 0usize;
    for byte_index in 0..32usize {
        for bit in 0..8u8 {
            let mut tampered = commit.clone();
            tampered.com[byte_index] ^= 1 << bit;

            assert!(
                aggregate_commitment(&[tampered], std::slice::from_ref(&reveal)).is_err(),
                "flipping bit {bit} of commitment byte {byte_index} was still accepted"
            );
            checked += 1;
        }
    }

    assert_eq!(checked, 32 * 8, "expected to cover every commitment bit");
}
