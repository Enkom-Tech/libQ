//! Equivalence tests for the batched (×8) AVX-512 permutation [`lib_q_keccak::p1600x8`].
//!
//! The batched path must produce, for each of the eight lanes, exactly what the scalar
//! single-state permutation produces for that lane's input. Eight *distinct* inputs catch
//! lane-crossing and transpose bugs.
//!
//! ## Hardware coverage
//! On a host without AVX-512 (e.g. any AMD Zen 1–3), `p1600x8` takes the scalar fallback, so
//! this test validates the dispatch and ×8 framing. On AVX-512 hardware (or a CI runner) the
//! exact same assertions drive the real `_mm512_*` permutation — this is the gate that must pass
//! before the intrinsic path is relied upon. The all-zero lane additionally pins the canonical
//! Keccak-f[1600] vector, which would catch a wrong rotate count or `ternarylogic` immediate.

use lib_q_keccak::{
    p1600,
    p1600x8,
};

/// Build a deterministic but per-lane-distinct state.
fn seeded_state(seed: u64) -> [u64; 25] {
    let mut s = [0u64; 25];
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
    let inputs: [[u64; 25]; 8] = [
        seeded_state(1),
        seeded_state(2),
        seeded_state(0xDEAD_BEEF),
        seeded_state(0xFEED_FACE),
        seeded_state(0x0BAD_F00D),
        seeded_state(0x1234_5678_9ABC_DEF0),
        seeded_state(u64::MAX),
        [0u64; 25], // include the all-zero state as a lane
    ];

    let mut expected = inputs;
    for state in expected.iter_mut() {
        p1600(state, rounds);
    }

    let mut batched = inputs;
    p1600x8(&mut batched, rounds);

    for (lane, (got, want)) in batched.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            got, want,
            "lane {lane} diverged from scalar reference at {rounds} rounds"
        );
    }
}

#[test]
fn x8_matches_scalar_keccak_f1600() {
    assert_batch_matches_scalar(24);
}

#[test]
fn x8_matches_scalar_turboshake_rounds() {
    assert_batch_matches_scalar(12);
}

#[test]
fn x8_matches_scalar_various_round_counts() {
    for rounds in [1usize, 2, 6, 12, 18, 23, 24] {
        assert_batch_matches_scalar(rounds);
    }
}

#[test]
fn x8_known_answer_f1600_zero_state() {
    let mut states = [[0u64; 25]; 8];
    p1600x8(&mut states, 24);

    const EXPECTED_LANE0: u64 = 0xF125_8F79_40E1_DDE7;
    for (lane, state) in states.iter().enumerate() {
        assert_eq!(
            state[0], EXPECTED_LANE0,
            "lane {lane} did not match the known Keccak-f[1600] vector"
        );
    }
}
