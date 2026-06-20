//! Equivalence tests for the batched (×4) permutation [`lib_q_keccak::p1600x4`].
//!
//! The batched path must produce, for each of the four lanes, exactly what the
//! scalar single-state permutation produces for that lane's input. Using four
//! *distinct* inputs is what catches lane-crossing and transpose bugs: if any
//! lane leaked into another, or the load/store transpose were wrong, at least one
//! lane would diverge from its scalar reference.

use lib_q_keccak::{
    p1600,
    p1600x4,
};

/// Build a deterministic but per-lane-distinct state.
fn seeded_state(seed: u64) -> [u64; 25] {
    let mut s = [0u64; 25];
    // A cheap xorshift-ish fill — just needs to differ per lane and exercise all bits.
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for lane in s.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *lane = x;
    }
    s
}

fn assert_batch_matches_scalar(rounds: usize) {
    // Four distinct inputs.
    let inputs: [[u64; 25]; 4] = [
        seeded_state(1),
        seeded_state(2),
        seeded_state(0xDEAD_BEEF),
        [0u64; 25], // include the all-zero state as a lane
    ];

    // Scalar reference: permute each independently.
    let mut expected = inputs;
    for state in expected.iter_mut() {
        p1600(state, rounds);
    }

    // Batched.
    let mut batched = inputs;
    p1600x4(&mut batched, rounds);

    for (lane, (got, want)) in batched.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            got, want,
            "lane {lane} diverged from scalar reference at {rounds} rounds"
        );
    }
}

#[test]
fn x4_matches_scalar_keccak_f1600() {
    // Full Keccak-f[1600].
    assert_batch_matches_scalar(24);
}

#[test]
fn x4_matches_scalar_turboshake_rounds() {
    // Reduced-round permutation used by TurboSHAKE / KangarooTwelve.
    assert_batch_matches_scalar(12);
}

#[test]
fn x4_matches_scalar_various_round_counts() {
    for rounds in [1usize, 2, 6, 12, 18, 23, 24] {
        assert_batch_matches_scalar(rounds);
    }
}

#[test]
fn x4_known_answer_f1600_zero_state() {
    // All four lanes start zero, so each must reach the canonical Keccak-f[1600]
    // fixed test vector (same one asserted in the crate-root doctest).
    let mut states = [[0u64; 25]; 4];
    p1600x4(&mut states, 24);

    const EXPECTED_LANE0: u64 = 0xF125_8F79_40E1_DDE7;
    for (lane, state) in states.iter().enumerate() {
        assert_eq!(
            state[0], EXPECTED_LANE0,
            "lane {lane} did not match the known Keccak-f[1600] vector"
        );
    }
}
