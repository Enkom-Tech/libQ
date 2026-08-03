//! M6a RED-first verification (raccoon-hardening-design §3.1.1 / §7 M6a): `dkg_reshare` is a
//! **change-of-committee key rotation**, not a proactive refresh — it preserves the group *secret*
//! but re-randomizes the group *commitment* `T`, and `T` **is** the verification key
//! (`lib-q-threshold-raccoon`'s `group_key`/public key). The existing
//! `reshare_is_binding_and_preserves_secret` test (kat_vectors.rs) never checks the group key at all.
//! This file executes that check and records what actually happens — it does not fix `dkg_reshare`.
//!
//! Run with `--release` (the resharing FS proofs are Gaussian-masking heavy).

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::{
    dkg_assemble_vk_set,
    dkg_eval_share,
    dkg_finalize_share,
    dkg_reshare,
    dkg_round1_commit,
    dkg_verify_share,
    lagrange_coeff_at_zero,
    setup,
};

/// Reshare a dealerless key to a fresh committee and reassemble both verification-key sets.
///
/// Returns `(old_group_key, new_group_key)` so callers can either assert equality (the falsifier,
/// §7 M6a) or inequality (the permanent pin, once the falsifier has been observed to fail).
fn reshare_and_assemble_both_vk_sets() -> (Vec<u8>, Vec<u8>) {
    let profile = setup();
    let mut rng = det_rng(0x99);

    // Every party deals; collect polys + commitments (mirrors kat_vectors.rs's existing test).
    let mut all_comms = Vec::new();
    let mut polys = Vec::new();
    for party in 1..=PARTIES {
        let (poly, comms) =
            dkg_round1_commit(&profile, PARTIES, THRESHOLD, party, &mut rng).expect("round1");
        polys.push(poly);
        all_comms.push(comms);
    }
    let old_vk = dkg_assemble_vk_set(&all_comms, PARTIES).expect("assemble old vk");

    // Finalize every party's share (needed so a threshold subset can reshare).
    let mut signing_shares = Vec::new();
    for i in 1..=PARTIES {
        let mut received = Vec::new();
        for poly in &polys {
            received.push(dkg_eval_share(poly, i, &mut rng).expect("eval"));
        }
        signing_shares.push(dkg_finalize_share(&received).expect("finalize"));
    }

    // A threshold subset reshares to a fresh committee (same size here; the group-key claim does not
    // depend on committee size).
    let subset = [1u8, 2, 3];
    let new_committee = [1u8, 2, 3, 4, 5];
    let new_t = 3u8;
    let mut new_comms = Vec::new();
    for &i in &subset {
        let share = &signing_shares[usize::from(i - 1)];
        let lambda = lagrange_coeff_at_zero(&subset, i).expect("lagrange");
        let round1 = dkg_reshare(share, lambda, &new_committee, new_t, &mut rng).expect("reshare");
        for sub in &round1.shares {
            assert!(
                dkg_verify_share(&round1.commitments, i, sub.recipient, sub),
                "reshared sub-share must verify (binding resharing) -- sanity check, not the point \
                 of this test"
            );
        }
        new_comms.push(round1.commitments);
    }
    let new_vk = dkg_assemble_vk_set(&new_comms, u8::try_from(new_committee.len()).unwrap())
        .expect("assemble new vk");

    (old_vk.group_key, new_vk.group_key)
}

/// THE FALSIFIER (design §3.1.1, §7 M6a). The design predicts this fails: `dkg_reshare` discards the
/// old commitment randomness (`decode_value_rand` result's `_old_rand` at dkg.rs, bound and dropped)
/// and samples **fresh** randomness for every resharing coefficient, so the reassembled group
/// commitment changes even though the underlying secret is preserved.
///
/// This test is intentionally landed and left RED -- see the M0 progress log
/// (raccoon-m0-progress.md) for the executed failure output. Do not "fix" this test by weakening the
/// assertion; the failure IS the finding. It stays `#[ignore]`d so normal `cargo test` runs green;
/// run it explicitly with `cargo test -p lib-q-dkg --release --test reshare_group_key -- --ignored`
/// to reproduce the recorded failure.
#[test]
#[ignore = "RED by design -- dkg_reshare does not preserve the group key (see M0 progress log); \
            kept in the suite as executed evidence, not something to fix here"]
fn reshare_does_not_preserve_group_key() {
    let (old_group_key, new_group_key) = reshare_and_assemble_both_vk_sets();
    assert_eq!(
        old_group_key, new_group_key,
        "dkg_reshare must preserve the group key (verification key) for it to be usable as a \
         proactive refresh"
    );
}

/// The permanent, green pin of the same fact, inverted (design §7 M6a: "keep it in the suite,
/// inverted, ... so the distinction between rotation and refresh is permanently pinned"). Passing
/// here means: resharing changes the verification key, i.e. `dkg_reshare` is a key-rotation
/// primitive, not a refresh primitive. If this test ever starts failing, `dkg_reshare`'s randomness
/// handling changed and every conclusion in raccoon-hardening-design.md §3.1 needs re-checking.
#[test]
fn reshare_rotates_the_group_key() {
    let (old_group_key, new_group_key) = reshare_and_assemble_both_vk_sets();
    assert_ne!(
        old_group_key, new_group_key,
        "dkg_reshare re-randomizes the group commitment -- if this ever holds (group key \
         preserved), dkg_reshare has become usable as a refresh primitive and the M6a finding is \
         stale"
    );
}
