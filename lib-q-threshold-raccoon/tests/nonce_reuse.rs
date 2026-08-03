//! Regression for the one-shot-masking fix (M0 item 1, design §2.1).
//!
//! `sign_round2` used to borrow `Round1State` (`&Round1State`), so nothing stopped a caller from
//! invoking it twice on the same state with two different messages — an honest retry loop after a
//! network timeout would do exactly this, not only a malicious caller. Because
//! `z_s,i = y_s,i + c·λ_i·value_i` broadcasts the uniform mask `y_s,i` **unmasked**, differencing two
//! such broadcasts cancels `y_s,i` and yields `(c_1 - c_2)·λ_i·value_i` — a relaxed opening of the
//! party's secret share. That recovery was executed and confirmed real against the pre-fix API
//! (`round1_state_reuse_recovers_share`, since removed — see the M0 progress log): two `sign_round2`
//! calls on one `Round1State` with different messages exactly recovered `value_1`.
//!
//! `sign_round2` now **consumes** `Round1State` by value, so reuse is a compile error rather than a
//! runtime hazard — pinned permanently by the `compile_fail` doctest on `sign_round2` in
//! `src/threshold.rs` (verified: attempting the double call there fails with
//! `E0382: use of moved value`). This file is the regression that one-shot usage still works.
//!
//! Run with `--release` (the dealerless DKG's FS proofs are Gaussian-masking heavy).

use lib_q_dkg::{
    dkg_run_honest,
    setup as dkg_setup,
};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_raccoon::threshold::{
    ZeroShareSeeds,
    aggregate_commitment,
    sign_round1,
    sign_round1_reveal,
    sign_round2,
};
use lib_q_threshold_raccoon::{
    SecretShare,
    ShareVerifier,
    ThresholdRaccoonPublicKey,
    group_commitment,
};

#[test]
fn round1_state_is_consumed_by_a_single_sign_round2_call() {
    let mut rng = new_deterministic_rng([0xA5u8; 32]);

    let kg = dkg_run_honest(&dkg_setup(), 5, 3, &mut rng).expect("dkg");
    let pk = ThresholdRaccoonPublicKey {
        threshold: kg.public_key.threshold,
        group_key: kg.public_key.group_key.clone(),
        share_verifiers: kg
            .public_key
            .share_verifiers
            .iter()
            .map(|v| ShareVerifier {
                index: v.index,
                verifying_key: v.verifying_key.clone(),
            })
            .collect(),
    };
    let shares: Vec<SecretShare> = kg
        .secret_shares
        .iter()
        .map(|s| SecretShare {
            index: s.index,
            threshold: s.threshold,
            share_bytes: s.share_bytes.clone(),
        })
        .collect();
    let seeds = ZeroShareSeeds::setup(5, &mut rng);
    let subset = [1u8, 2, 3];
    let t = group_commitment(&pk).expect("group commitment");

    let mut states = Vec::new();
    let mut commits = Vec::new();
    for (k, &idx) in subset.iter().enumerate() {
        let mut r = new_deterministic_rng([0x5A ^ idx ^ (k as u8); 32]);
        let (st, com) = sign_round1(idx, &mut r);
        states.push(st);
        commits.push(com);
    }
    let reveals: Vec<_> = states.iter().map(sign_round1_reveal).collect();
    let w = aggregate_commitment(&commits, &reveals).expect("aggregate commitment");

    // A single, legitimate round-3 call still works: `sign_round2` consumes `state1` by value.
    let mut states = states.into_iter();
    let state1 = states.next().expect("state 1");
    let share1 = shares.iter().find(|s| s.index == 1).expect("share 1");
    let msg = b"one-shot-signing";
    let partial = sign_round2(state1, share1, &subset, &t, msg, &w, &seeds).expect("round2");
    assert_eq!(partial.index, 1);

    // `state1` was moved into the call above; a second call would not compile (E0382) — see the
    // `compile_fail` doctest on `sign_round2` (src/threshold.rs) for the permanent pin of that fact.
}
