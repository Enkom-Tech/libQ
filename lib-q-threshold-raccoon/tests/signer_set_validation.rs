//! Round-3 signer-set validation and the zero-share seed constructor. Run with `--release`.
//!
//! `sign_round2` derives the party's Lagrange weight and zero-share mask from the caller-supplied
//! `subset`. A sub-threshold subset is not a qualified signing set: the weight is wrong, and with a
//! singleton subset the zero-share is empty, so the round-3 broadcast is the unmasked
//! `y_r + c·rand(i)`. A repeated index skews both the weight and the mask. Both are refused before
//! the share is touched.

use lib_q_dkg::lattice::bdlop::KAPPA;
use lib_q_dkg::lattice::ring::{RQ_BYTES, centered_coeffs, ring_mul, ring_sub, rq_from_le_bytes};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_raccoon::signer::{BETA_R, challenge};
use lib_q_threshold_raccoon::threshold::{
    ZeroShareSeeds, aggregate_commitment, sign_round1, sign_round1_reveal, sign_round2,
};
use lib_q_threshold_raccoon::{
    KeygenSharesOutput, RaccoonError, SecretShare, group_commitment, keygen_shares, setup,
};

fn keygen_3_of_5() -> KeygenSharesOutput {
    let mut rng = new_deterministic_rng([0xA7u8; 32]);
    keygen_shares(&setup(), 3, 5, &mut rng).expect("keygen")
}

/// Run rounds 1–2 for `subset` and return party `me`'s round-3 result over `round3_subset`.
fn round3_for(
    kg: &KeygenSharesOutput,
    me: u8,
    round3_subset: &[u8],
    seeds: &ZeroShareSeeds,
) -> Result<lib_q_threshold_raccoon::threshold::PartialSignature, RaccoonError> {
    let t = group_commitment(&kg.public_key).expect("group commitment");
    let mut rng = new_deterministic_rng([me; 32]);
    let (state, commit) = sign_round1(me, &mut rng);
    let reveal = sign_round1_reveal(&state);
    let w = aggregate_commitment(&[commit], &[reveal]).expect("aggregate commitment");
    let share: &SecretShare = kg
        .secret_shares
        .iter()
        .find(|s| s.index == me)
        .expect("share");
    sign_round2(state, share, round3_subset, &t, b"msg", &w, seeds)
}

#[test]
fn sub_threshold_subset_is_refused() {
    let kg = keygen_3_of_5();
    let mut rng = new_deterministic_rng([0x5Eu8; 32]);
    let seeds = ZeroShareSeeds::setup(5, &mut rng);
    for subset in [&[1u8][..], &[1, 2][..]] {
        assert_eq!(
            round3_for(&kg, 1, subset, &seeds).err(),
            Some(RaccoonError::InvalidSignerSet),
            "subset {subset:?} is below threshold 3 and must be refused"
        );
    }
}

/// What the sub-threshold refusal prevents: with a singleton subset the zero-share is empty and
/// `λ = 1`, so `z_r_masked − c·rand(1)` is the bare short Gaussian mask — the broadcast carries no
/// zero-share at all. This drives the same arithmetic through the public ring API on a subset that
/// *is* qualified, to show the check is the only thing standing between a caller and that exposure.
#[test]
fn singleton_subset_would_broadcast_unmasked_response() {
    let kg = keygen_3_of_5();
    let t = group_commitment(&kg.public_key).expect("group commitment");
    let mut rng = new_deterministic_rng([0x11u8; 32]);
    let (state, commit) = sign_round1(1, &mut rng);
    let w = aggregate_commitment(&[commit], &[sign_round1_reveal(&state)]).expect("aggregate");
    let c = challenge(&t, b"msg", &w);
    let share = &kg.secret_shares[0];
    let mut rng = new_deterministic_rng([0x5Eu8; 32]);
    let seeds = ZeroShareSeeds::setup(5, &mut rng);
    match sign_round2(state, share, &[1], &t, b"msg", &w, &seeds) {
        Err(e) => assert_eq!(e, RaccoonError::InvalidSignerSet),
        Ok(partial) => {
            // Pre-fix behaviour: demonstrate the exposure, then fail.
            let rand_k = |k: usize| {
                let start = RQ_BYTES * (1 + k);
                rq_from_le_bytes(&share.share_bytes[start..start + RQ_BYTES]).expect("rand")
            };
            let max_unmasked = (0..KAPPA)
                .map(|k| ring_sub(&partial.z_r_masked[k], &ring_mul(&c, &rand_k(k))))
                .flat_map(|p| centered_coeffs(&p))
                .map(i64::abs)
                .max()
                .unwrap_or(0);
            panic!(
                "singleton subset accepted: max |z_r_masked - c*rand(1)| = {max_unmasked} \
                 (BETA_R = {BETA_R}) — the round-3 broadcast is the unmasked y_r + c*rand(1)"
            );
        }
    }
}

#[test]
fn repeated_or_zero_index_is_refused() {
    let kg = keygen_3_of_5();
    let mut rng = new_deterministic_rng([0x5Eu8; 32]);
    let seeds = ZeroShareSeeds::setup(5, &mut rng);
    for subset in [&[1u8, 2, 2][..], &[1, 1, 2, 3][..], &[0, 1, 2, 3][..]] {
        assert_eq!(
            round3_for(&kg, 1, subset, &seeds).err(),
            Some(RaccoonError::InvalidSignerSet),
            "subset {subset:?} must be refused"
        );
    }
}

#[test]
fn qualified_subset_is_still_accepted() {
    let kg = keygen_3_of_5();
    let mut rng = new_deterministic_rng([0x5Eu8; 32]);
    let seeds = ZeroShareSeeds::setup(5, &mut rng);
    assert!(round3_for(&kg, 1, &[1, 3, 5], &seeds).is_ok());
    assert!(round3_for(&kg, 1, &[1, 2, 3, 4, 5], &seeds).is_ok());
}

#[test]
fn from_pairwise_builds_a_party_local_seed_set() {
    // Party 1's own view for subset {1, 3, 5}: only the seeds it shares with 3 and 5.
    let local = ZeroShareSeeds::from_pairwise(vec![(1, 3, [0x13; 32]), (1, 5, [0x15; 32])])
        .expect("canonical entries");
    let kg = keygen_3_of_5();
    assert!(round3_for(&kg, 1, &[1, 3, 5], &local).is_ok());
    // A subset needing a seed party 1 does not hold fails closed.
    assert_eq!(
        round3_for(&kg, 1, &[1, 2, 3], &local).err(),
        Some(RaccoonError::InvalidSignerSet)
    );
}

#[test]
fn from_pairwise_rejects_non_canonical_entries() {
    for entries in [
        vec![(0u8, 1u8, [0u8; 32])],
        vec![(2, 1, [0; 32])],
        vec![(1, 1, [0; 32])],
        vec![(1, 2, [0; 32]), (1, 2, [1; 32])],
    ] {
        assert_eq!(
            ZeroShareSeeds::from_pairwise(entries.clone()).err(),
            Some(RaccoonError::InvalidSeedEntry),
            "{:?} must be rejected",
            entries.iter().map(|(i, j, _)| (*i, *j)).collect::<Vec<_>>()
        );
    }
}
