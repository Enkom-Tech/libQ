//! ENK-142 RED-first verification: the dealerless DKG has no proactive-refresh lifecycle
//! operation, so a custody set that is compromised *slowly* -- below threshold in any single
//! epoch, but accumulating across epochs -- eventually reconstructs the group secret from shares
//! that all remain valid forever.
//!
//! `rg` across `gip` and `libQ` for `dkg_refresh|proactive.?refresh|refresh.?share` (2026-08-30)
//! finds no such operation anywhere. The only resharing primitive that exists,
//! [`lib_q_dkg::dkg_reshare`], is a **change-of-committee key rotation**, not a same-committee
//! refresh: `reshare_group_key.rs` (M6a) already proves, with an executed RED test, that it
//! re-randomizes the group's public identity (the commitment `T`, which is byte-for-byte the
//! `lib-q-threshold-kem-lattice` public key -- see `public_key_from_dkg`'s `t0 = B0*r`) even
//! though it preserves the secret. Reusing `dkg_reshare` for same-committee refresh would still
//! rotate the identity every epoch, which fails ENK-142's own "FCK/identity must survive refresh"
//! and "threshold-KEM decap continues to work post-refresh" acceptance criteria. A real fix needs a
//! NEW primitive: a same-committee, identity-preserving refresh (Herzberg-style joint zero-sharing
//! whose commitment randomness ALSO cancels across the group, so `T` is unchanged) -- e.g. along
//! the lines of IACR 2022/1586. That primitive does not exist in `lib-q-dkg` today.
//!
//! Run with `--release` (Gaussian-masking FS proofs are heavy in debug builds).

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::lattice::ring::{
    Rq,
    centered_coeffs,
    ring_add,
    scalar_mul,
};
use lib_q_dkg::{
    dkg_eval_share,
    dkg_round1_commit,
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

/// GREEN -- pins today's real, vulnerable behaviour (the ENK-142 premise, executed rather than
/// assumed): with no refresh lifecycle operation, a `t-1`-share capture in "epoch N" plus a
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

    // Epoch N+1: no refresh ran (there is no such operation in this codebase), so the polynomial
    // is still exactly the one from epoch N. The attacker slowly captures a further t-1 shares,
    // from DIFFERENT custodians: {3, 4}.
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
        "epoch-N union epoch-(N+1) reconstructs the TRUE group secret -- this IS the ENK-142 gap, \
         observed rather than assumed"
    );
    assert_eq!(
        centered_coeffs(&via_subset_b),
        centered_coeffs(&ground_truth),
        "reconstruction is not a single-basis fluke: a second, differently-straddling t-subset of \
         the same pooled union agrees exactly"
    );
}

/// Positive control named explicitly in ENK-142's acceptance: "an honest quorum within one epoch
/// still can [reconstruct]". Pinned so the RED gap above has an explicit, executed contrast rather
/// than an implicit assumption that Shamir/Feldman reconstruction works at all.
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

/// THE TARGET (ENK-142's actual acceptance criterion). RED by design: there is no refresh
/// primitive to make this pass. Once a same-committee, identity-preserving refresh ceremony exists
/// and is actually run between the two capture windows, epoch-N shares become points on a
/// DIFFERENT (freshly re-randomized, but secret- and identity-preserving) polynomial than
/// epoch-(N+1) shares, so pooling `t-1` of each no longer yields `t` points on one polynomial and
/// this assertion should start passing.
///
/// Landed and left RED on purpose, exactly like `lib-q-dkg`'s own `reshare_group_key.rs` M6a
/// precedent: `#[ignore]`d so a normal `cargo test` run stays green, reproducible with
/// `cargo test -p lib-q-dkg --release --test proactive_refresh_gap -- --ignored`. Do not "fix" this
/// by weakening the assertion, and do not "fix" it by wiring `dkg_reshare` as the refresh op with
/// `new_committee == old_committee` -- `reshare_group_key.rs` already proves that primitive
/// re-randomizes the group's public identity (the KEM `t0` public key) on every call, which is
/// disqualifying on its own.
#[test]
#[ignore = "RED by design -- no refresh primitive exists yet (ENK-142); kept in the suite as \
            executed evidence, not something to fix here"]
fn cross_epoch_union_cannot_reconstruct_after_refresh() {
    let values = run_ceremony_and_collect_values();
    let ground_truth = interpolate_zero(&[1, 2, 3, 4, 5], &values);

    // Identical capture pattern to the RED-observed test above. Absent an actual refresh ceremony
    // mutating the live shares between the two captures, this is definitionally the same data, so
    // the assertion below is expected to FAIL today.
    let via_union = interpolate_zero(&[1, 2, 3], &values);
    assert_ne!(
        centered_coeffs(&via_union),
        centered_coeffs(&ground_truth),
        "post-refresh, a cross-epoch union must NOT reconstruct the group secret"
    );
}
