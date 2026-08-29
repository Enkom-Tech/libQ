//! ENK-142 verification: the dealerless DKG has a same-committee, identity-preserving
//! proactive-refresh lifecycle operation ([`dkg_run_honest_refresh`], `dkg.rs`), closing the gap
//! where a custody set compromised *slowly* -- below threshold in any single epoch, but
//! accumulating across epochs -- could eventually reconstruct the group secret from shares that
//! all remained valid forever.
//!
//! `rg` across `gip` and `libQ` for `dkg_refresh|proactive.?refresh|refresh.?share` (2026-08-30)
//! found no such operation anywhere. The only resharing primitive that existed,
//! [`lib_q_dkg::dkg_reshare`], is a **change-of-committee key rotation**, not a same-committee
//! refresh: `reshare_group_key.rs` (M6a) proves, with an executed RED test, that it re-randomizes
//! the group's public identity (the commitment `T`, byte-for-byte the
//! `lib-q-threshold-kem-lattice` public key -- see `public_key_from_dkg`'s `t0 = B0*r`) even
//! though it preserves the secret. Reusing `dkg_reshare` for same-committee refresh would still
//! rotate the identity every epoch, failing ENK-142's own "FCK/identity must survive refresh" and
//! "threshold-KEM decap continues to work post-refresh" acceptance criteria.
//!
//! The fix landed here is [`dkg_run_honest_refresh`] (and its building blocks
//! `dkg_round1_commit_refresh` / `dkg_check_zero_dealer` / `dkg_apply_refresh` /
//! `dkg_apply_refresh_vk`, all in `dkg.rs`): a Herzberg-style joint zero-sharing whose
//! constant-term commitment randomness is pinned to the public, randomness-free zero commitment,
//! so combining a qualified round's deltas into the live shares changes every higher-degree
//! coefficient while leaving the constant term -- and the BDLOP commitment randomness that opens
//! it into `t0` -- byte-identical.
//!
//! Run with `--release` (Gaussian-masking FS proofs are heavy in debug builds).

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
    centered_coeffs,
    ring_add,
    rq_from_le_bytes,
    scalar_mul,
};
use lib_q_dkg::{
    SigningShare,
    dkg_eval_share,
    dkg_round1_commit,
    dkg_run_honest,
    dkg_run_honest_refresh,
    lagrange_coeff_at_zero,
    setup,
};

/// Lagrange-interpolate a subset's finalized share VALUES at `x = 0` to recover the group secret's
/// constant term. Identical in spirit to `kat_vectors.rs`'s private helper of the same name (not
/// exported, so re-derived here) -- Shamir/Feldman guarantees any `t`-size subset of points on the
/// same degree-`(t-1)` polynomial agrees.
fn interpolate_zero(subset: &[u8], values: &[(u8, Rq)]) -> Rq {
    let mut acc = Rq::zero();
    for &i in subset {
        let lam = lagrange_coeff_at_zero(subset, i).expect("lagrange");
        let v = &values.iter().find(|(idx, _)| *idx == i).expect("value").1;
        acc = ring_add(&acc, &scalar_mul(v, lam));
    }
    acc
}

/// Decode a finalized [`SigningShare`]'s VALUE component -- the raw Shamir-style point each
/// custodian actually holds (the first [`RQ_BYTES`] of `share_bytes`, ahead of the `rand`
/// component; see `dkg.rs`'s private `encode_value_rand`).
fn share_value(share: &SigningShare) -> Rq {
    rq_from_le_bytes(&share.share_bytes[..RQ_BYTES]).expect("well-formed finalized share")
}

/// Run one honest `t`-of-`n` dealerless DKG (every party deals to every party) and return each
/// party's finalized share VALUE `Σ_dealer f_dealer(i)` -- the raw Shamir-style point each
/// custodian actually holds. Mirrors `kat_vectors.rs`'s `reshare_is_binding_and_preserves_secret`
/// setup exactly, so this is the real DKG output, not a stand-in.
fn run_ceremony_and_collect_values() -> Vec<(u8, Rq)> {
    let profile = setup();
    let mut rng = det_rng(0xE1);

    let mut polys = Vec::new();
    for party in 1..=PARTIES {
        let (poly, _comms) =
            dkg_round1_commit(&profile, PARTIES, THRESHOLD, party, &mut rng).expect("round1");
        polys.push(poly);
    }

    let mut values = Vec::new();
    for i in 1..=PARTIES {
        let mut val = Rq::zero();
        for poly in &polys {
            let s = dkg_eval_share(poly, i, &mut rng).expect("eval");
            val = ring_add(&val, &s.value);
        }
        values.push((i, val));
    }
    values
}

/// GREEN -- pins today's real, vulnerable behaviour of a committee that never runs a refresh (the
/// ENK-142 premise, executed rather than assumed): a `t-1`-share capture in "epoch N" plus a
/// DISJOINT `t-1`-share capture in a later "epoch N+1" reconstructs the group secret, because
/// nothing about any share changed between the two captures -- they are points on the very same
/// never-refreshed polynomial. Cross-checked against two different `t`-subsets of the pooled union
/// (not one Lagrange-basis fluke) and against the full-committee ground truth.
#[test]
fn cross_epoch_share_union_reconstructs_without_refresh() {
    let values = run_ceremony_and_collect_values();
    let ground_truth = interpolate_zero(&[1, 2, 3, 4, 5], &values);

    // Epoch N: attacker captures custodians {1, 2} -- one short of threshold (t=3), alone useless.
    let epoch_n: [u8; 2] = [1, 2];
    assert_eq!(
        epoch_n.len(),
        usize::from(THRESHOLD) - 1,
        "epoch-N capture must be sub-threshold"
    );

    // Epoch N+1: no refresh ran on THIS committee, so the polynomial is still exactly the one from
    // epoch N. The attacker slowly captures a further t-1 shares, from DIFFERENT custodians: {3, 4}.
    let epoch_n_plus_1: [u8; 2] = [3, 4];
    assert_eq!(
        epoch_n_plus_1.len(),
        usize::from(THRESHOLD) - 1,
        "epoch-(N+1) capture must also be sub-threshold on its own"
    );

    // The union spans two "epochs" but is really 4 points on one polynomial that was never
    // refreshed in between.
    let union_len = epoch_n.len() + epoch_n_plus_1.len();
    assert!(
        union_len >= usize::from(THRESHOLD),
        "pooled capture must reach threshold"
    );

    let via_subset_a = interpolate_zero(&[1, 2, 3], &values); // epoch-N pair + one epoch-(N+1) share
    let via_subset_b = interpolate_zero(&[2, 3, 4], &values); // straddles both captures differently

    assert_eq!(
        centered_coeffs(&via_subset_a),
        centered_coeffs(&ground_truth),
        "epoch-N union epoch-(N+1) reconstructs the TRUE group secret on an un-refreshed \
         committee -- this IS the ENK-142 gap, observed rather than assumed"
    );
    assert_eq!(
        centered_coeffs(&via_subset_b),
        centered_coeffs(&ground_truth),
        "reconstruction is not a single-basis fluke: a second, differently-straddling t-subset of \
         the same pooled union agrees exactly"
    );
}

/// Positive control named explicitly in ENK-142's acceptance: "an honest quorum within one epoch
/// still can [reconstruct]". Pinned so the refresh test below has an explicit, executed contrast
/// rather than an implicit assumption that Shamir/Feldman reconstruction works at all.
#[test]
fn honest_quorum_within_one_epoch_reconstructs() {
    let values = run_ceremony_and_collect_values();
    let ground_truth = interpolate_zero(&[1, 2, 3, 4, 5], &values);
    let quorum = interpolate_zero(&[1, 2, 3], &values);
    assert_eq!(
        centered_coeffs(&quorum),
        centered_coeffs(&ground_truth),
        "a full threshold quorum captured within one epoch must reconstruct"
    );
}

/// THE TARGET (ENK-142's actual acceptance criterion) -- GREEN: a same-committee,
/// identity-preserving proactive refresh ([`dkg_run_honest_refresh`]) runs on the LIVE committee
/// between the two capture windows (no committee change, no custody outage -- it is just another
/// DKG-shaped round over the existing mesh). Epoch-N shares are therefore points on a DIFFERENT
/// (freshly re-randomized, but secret- and identity-preserving) polynomial than epoch-(N+1)
/// shares, so pooling `t-1` of each no longer yields `t` points on one polynomial.
///
/// This test used to be `#[ignore]`d as RED-by-design. The fix is `dkg_run_honest_refresh`
/// (Herzberg-style same-committee zero-sharing) -- NOT `dkg_reshare` with
/// `new_committee == old_committee`, which `reshare_group_key.rs`'s own M6a RED test already
/// proves re-randomizes the group's public identity (the KEM `t0` public key) on every call.
#[test]
fn cross_epoch_union_cannot_reconstruct_after_refresh() {
    let profile = setup();
    let mut rng = det_rng(0xE2);

    // Epoch N: the live committee's shares right after keygen.
    let epoch_n_output = dkg_run_honest(&profile, PARTIES, THRESHOLD, &mut rng).expect("keygen");
    let epoch_n_values: Vec<(u8, Rq)> = epoch_n_output
        .secret_shares
        .iter()
        .map(|s| (s.index, share_value(s)))
        .collect();

    // A proactive refresh runs on the SAME committee -- between epoch N and epoch N+1 -- with no
    // key reconstruction and no custody outage.
    let epoch_n_plus_1_output =
        dkg_run_honest_refresh(&profile, PARTIES, THRESHOLD, &epoch_n_output, &mut rng)
            .expect("refresh");

    // The refresh preserves the group's public identity: `t0 = B0*r`, the
    // lib-q-threshold-kem-lattice public key, is exactly `group_key`'s `t0` half
    // (`public_key_from_dkg`), so byte-identical `group_key` bytes IS identity preservation.
    assert_eq!(
        epoch_n_output.public_key.group_key, epoch_n_plus_1_output.public_key.group_key,
        "a proactive refresh must preserve the group's public identity -- unlike dkg_reshare (see \
         reshare_group_key.rs)"
    );

    let epoch_n_plus_1_values: Vec<(u8, Rq)> = epoch_n_plus_1_output
        .secret_shares
        .iter()
        .map(|s| (s.index, share_value(s)))
        .collect();

    // Ground truth: the (unchanged) group secret, reconstructible from a full epoch-(N+1) quorum.
    let ground_truth = interpolate_zero(&[1, 2, 3, 4, 5], &epoch_n_plus_1_values);
    assert_eq!(
        centered_coeffs(&interpolate_zero(&[1, 2, 3, 4, 5], &epoch_n_values)),
        centered_coeffs(&ground_truth),
        "the refresh must preserve the group secret itself, not just its public commitment"
    );

    // Positive control: an honest quorum captured wholly within epoch N+1 still reconstructs.
    assert_eq!(
        centered_coeffs(&interpolate_zero(&[1, 2, 3], &epoch_n_plus_1_values)),
        centered_coeffs(&ground_truth),
        "an honest quorum within one epoch must still reconstruct"
    );

    // THE ACCEPTANCE CRITERION: t-1 shares from epoch N ({1,2}) pooled with a DISJOINT t-1 shares
    // from epoch N+1 ({3,4}) must NOT reconstruct -- they are points on two different polynomials
    // now, agreeing only at x=0 (the secret they were both careful to preserve).
    let mut pooled: Vec<(u8, Rq)> = Vec::new();
    for &i in &[1u8, 2] {
        let v = epoch_n_values
            .iter()
            .find(|(idx, _)| *idx == i)
            .unwrap()
            .1
            .clone();
        pooled.push((i, v));
    }
    for &i in &[3u8, 4] {
        let v = epoch_n_plus_1_values
            .iter()
            .find(|(idx, _)| *idx == i)
            .unwrap()
            .1
            .clone();
        pooled.push((i, v));
    }
    let via_subset_a = interpolate_zero(&[1, 2, 3], &pooled);
    let via_subset_b = interpolate_zero(&[2, 3, 4], &pooled);
    assert_ne!(
        centered_coeffs(&via_subset_a),
        centered_coeffs(&ground_truth),
        "post-refresh, a cross-epoch union must NOT reconstruct the group secret"
    );
    assert_ne!(
        centered_coeffs(&via_subset_b),
        centered_coeffs(&ground_truth),
        "not a single-basis fluke: a second, differently-straddling cross-epoch subset also fails \
         to reconstruct"
    );
}
