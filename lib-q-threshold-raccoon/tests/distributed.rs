//! Distributed t-of-n threshold signing simulation (no key reconstruction). Run with `--release`.
//!
//! The harness plays all `t` parties locally through the 3-round protocol (commit → reveal →
//! respond) and checks the aggregated signature verifies — each party uses only its own share.

use lib_q_dkg::{
    dkg_run_honest,
    setup as dkg_setup,
};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_raccoon::threshold::{
    PartialSignature,
    Round1Commit,
    Round1Reveal,
    Round1State,
    ZeroShareSeeds,
    aggregate,
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
    verify,
};

/// Drive the full 3-round protocol for `subset` and return the aggregated signature.
fn run_protocol(
    pk: &ThresholdRaccoonPublicKey,
    shares: &[SecretShare],
    subset: &[u8],
    seeds: &ZeroShareSeeds,
    msg: &[u8],
    seed: u8,
) -> lib_q_threshold_raccoon::Signature {
    let t = group_commitment(pk).expect("group commitment");

    // Round 1: each party commits to its first message.
    let mut states: Vec<Round1State> = Vec::new();
    let mut commits: Vec<Round1Commit> = Vec::new();
    for (k, &idx) in subset.iter().enumerate() {
        let mut rng = new_deterministic_rng([seed ^ idx ^ (k as u8); 32]);
        let (st, com) = sign_round1(idx, &mut rng);
        states.push(st);
        commits.push(com);
    }

    // Round 2: reveal + aggregate the first message.
    let reveals: Vec<Round1Reveal> = states.iter().map(sign_round1_reveal).collect();
    let w = aggregate_commitment(&commits, &reveals).expect("aggregate commitment");

    // Round 3: each party emits its masked partial.
    let partials: Vec<PartialSignature> = states
        .iter()
        .map(|st| {
            let share = shares.iter().find(|s| s.index == st.index).expect("share");
            sign_round2(st, share, subset, &t, msg, &w, seeds).expect("round2")
        })
        .collect();

    aggregate(&partials, subset, &t, msg, &w).expect("aggregate")
}

#[test]
fn distributed_dealerless_threshold_signature() {
    let mut rng = new_deterministic_rng([0x90u8; 32]);

    // Dealerless DKG → shares + group key (this signer's key material, byte-identical).
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
    let msg = b"distributed-threshold-raccoon";

    // Subset {1,2,3} runs the distributed protocol → valid signature.
    let sig = run_protocol(&pk, &shares, &[1, 2, 3], &seeds, msg, 0x10);
    assert!(verify(&pk, msg, &sig), "distributed signature must verify");
    assert!(!verify(&pk, b"different", &sig), "wrong message must fail");

    // A DIFFERENT subset {2,4,5} produces another valid signature for the same key.
    let sig2 = run_protocol(&pk, &shares, &[2, 4, 5], &seeds, msg, 0x20);
    assert!(
        verify(&pk, msg, &sig2),
        "any qualified subset signs for the same key"
    );
}

#[test]
fn tampered_round1_opening_is_rejected() {
    let subset = [1u8, 2, 3];
    let mut states = Vec::new();
    let mut commits = Vec::new();
    for (k, &idx) in subset.iter().enumerate() {
        let mut r = new_deterministic_rng([0x33 ^ idx ^ (k as u8); 32]);
        let (st, com) = sign_round1(idx, &mut r);
        states.push(st);
        commits.push(com);
    }
    // Party 2 reveals a w that doesn't match its commitment → aggregation must reject.
    let mut reveals: Vec<Round1Reveal> = states.iter().map(sign_round1_reveal).collect();
    reveals[1].w.t1.coeffs[0] ^= 1;
    assert!(
        aggregate_commitment(&commits, &reveals).is_err(),
        "a reveal inconsistent with its commitment must be rejected",
    );
}
