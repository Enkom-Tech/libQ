//! The public values verifiable partial decapsulation needs — board card `ENK-52` item 2.
//!
//! That item was blocked by something that is not a proof obligation: this crate **discarded the
//! commitments a verifier would check against**. `keygen_shares` built all `t` BDLOP coefficient
//! commitments and kept only `encode_t0(&commitments[0].t0)`; `public_key_from_dkg` read
//! `vk.group_key` and ignored `vk.share_verifiers` entirely. A verifier handed a
//! `PartialDecap { index, value }` therefore had no public value binding it to party `index`'s
//! share, and no proof system can close that — the statement has no public input to refer to.
//!
//! These tests do not verify a partial decapsulation, and this crate still does not. They assert
//! the weaker thing that had to be true first: the commitments are published, and they are the
//! **correct** ones — each party's share opens to the Feldman evaluation of the published
//! coefficient commitments at that party's index. Publishing the wrong bytes would satisfy
//! "present" and fail this.

use lib_q_dkg::lattice::bdlop::{
    self,
    Commitment,
    KAPPA,
    MU,
};
use lib_q_dkg::lattice::ring::{
    RQ_BYTES,
    Rq,
    rq_from_le_bytes,
};
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::{
    ThresholdKemLatticeProfileV1,
    keygen_shares,
};

/// Inverse of the crate's `encode_commitment`: `MU` `t0` elements followed by `t1`.
fn decode_commitment(bytes: &[u8]) -> Commitment {
    assert_eq!(
        bytes.len(),
        (MU + 1) * RQ_BYTES,
        "commitment encoding is not (MU + 1) ring elements"
    );
    let t0: Vec<Rq> = (0..MU)
        .map(|i| rq_from_le_bytes(&bytes[i * RQ_BYTES..(i + 1) * RQ_BYTES]).expect("t0 element"))
        .collect();
    let t1 = rq_from_le_bytes(&bytes[MU * RQ_BYTES..]).expect("t1 element");
    Commitment { t0, t1 }
}

/// Split an encoded share into its `value` and `rand` ring elements.
fn decode_share(bytes: &[u8]) -> (Rq, Vec<Rq>) {
    assert_eq!(bytes.len(), RQ_BYTES * (1 + KAPPA));
    let value = rq_from_le_bytes(&bytes[..RQ_BYTES]).expect("value");
    let rand = (0..KAPPA)
        .map(|k| {
            let start = RQ_BYTES * (1 + k);
            rq_from_le_bytes(&bytes[start..start + RQ_BYTES]).expect("rand element")
        })
        .collect();
    (value, rand)
}

/// **The Feldman relation.** For every party `i`, `commit(share_i.value; share_i.rand)` must equal
/// `Σ_j C_j · i^j` over the published coefficient commitments. This is precisely the check a
/// cheater-identification verifier performs, and it can only be run because the commitments are
/// now published.
#[test]
fn published_coefficient_commitments_open_every_share() {
    let profile = ThresholdKemLatticeProfileV1::default();
    let mut rng = new_deterministic_rng([0x5Au8; 32]);
    let out = keygen_shares(&profile, 3, 5, &mut rng).expect("keygen");

    assert_eq!(
        out.coefficient_commitments.len(),
        3,
        "expected one commitment per sharing-polynomial coefficient (t = 3); the crate used to \
         publish only the t0 half of C_0"
    );

    let comms: Vec<Commitment> = out
        .coefficient_commitments
        .iter()
        .map(|b| decode_commitment(b))
        .collect();
    let key = bdlop::key();

    assert_eq!(out.secret_shares.len(), 5);
    for share in &out.secret_shares {
        let (value, rand) = decode_share(&share.share_bytes);
        let rand: [Rq; KAPPA] = rand.try_into().expect("KAPPA randomness elements");
        let opened = bdlop::commit(key, &value, &rand);
        let expected = bdlop::eval_commitments(&comms, share.index);
        assert!(
            bdlop::commit_ct_eq(&opened, &expected),
            "party {}'s share does not open to the Feldman evaluation of the published \
             commitments — the published bytes are not the commitments to this sharing polynomial",
            share.index
        );
    }
}

/// The KEM public key must remain exactly the `t0` half of `C_0`. Publishing the full commitments
/// is additive: it must not have changed the wire that encapsulation uses.
#[test]
fn public_key_is_still_the_t0_half_of_the_constant_term_commitment() {
    let profile = ThresholdKemLatticeProfileV1::default();
    let mut rng = new_deterministic_rng([0xA5u8; 32]);
    let out = keygen_shares(&profile, 2, 3, &mut rng).expect("keygen");

    let c0 = &out.coefficient_commitments[0];
    assert_eq!(
        out.public_key.t0_bytes,
        c0[..MU * RQ_BYTES],
        "the public key is no longer the t0 prefix of the constant-term commitment — the v1 wire \
         moved, which this change was specifically not supposed to do"
    );
    assert_eq!(out.public_key.t0_bytes.len(), MU * RQ_BYTES);
}

/// A share from a *different* keygen must not open against these commitments. Without this, the
/// first test would pass against a `commit_ct_eq` that always returned true.
#[test]
fn a_foreign_share_does_not_open_against_the_published_commitments() {
    let profile = ThresholdKemLatticeProfileV1::default();
    let mut rng_a = new_deterministic_rng([0x01u8; 32]);
    let mut rng_b = new_deterministic_rng([0x02u8; 32]);
    let a = keygen_shares(&profile, 3, 5, &mut rng_a).expect("keygen a");
    let b = keygen_shares(&profile, 3, 5, &mut rng_b).expect("keygen b");

    let comms: Vec<Commitment> = a
        .coefficient_commitments
        .iter()
        .map(|x| decode_commitment(x))
        .collect();
    let key = bdlop::key();

    let foreign = &b.secret_shares[0];
    let (value, rand) = decode_share(&foreign.share_bytes);
    let rand: [Rq; KAPPA] = rand.try_into().expect("KAPPA randomness elements");
    let opened = bdlop::commit(key, &value, &rand);
    let expected = bdlop::eval_commitments(&comms, foreign.index);
    assert!(
        !bdlop::commit_ct_eq(&opened, &expected),
        "a share from an unrelated keygen opened against these commitments — the check is vacuous"
    );
}

/// The dealerless half of the same gap: `lib_q_dkg::VerificationKeySet` already carries per-party
/// verification keys, and `public_key_from_dkg` dropped them at this crate's boundary.
/// `share_verifiers_from_dkg` carries them across; this asserts they arrive, one per party, at the
/// same `(MU + 1)` ring-element layout the dealt path publishes, with the DKG's own bytes intact.
#[test]
fn dkg_share_verifiers_survive_the_crate_boundary() {
    let dkg_profile = lib_q_dkg::DkgProfileV1::default();
    let mut rng = new_deterministic_rng([0x33u8; 32]);
    let out = lib_q_dkg::dkg_run_honest(&dkg_profile, 3, 2, &mut rng).expect("dkg");

    let verifiers = lib_q_threshold_kem_lattice::share_verifiers_from_dkg(&out.public_key)
        .expect("share verifiers");

    assert_eq!(verifiers.len(), out.public_key.share_verifiers.len());
    assert_eq!(verifiers.len(), 3, "one verification key per party");
    for (got, want) in verifiers.iter().zip(out.public_key.share_verifiers.iter()) {
        assert_eq!(got.index, want.index);
        assert_ne!(got.index, 0, "indices are 1-based");
        assert_eq!(
            got.commitment_bytes.len(),
            (MU + 1) * RQ_BYTES,
            "layout must match the dealt path's coefficient commitments"
        );
        assert_eq!(
            got.commitment_bytes, want.verifying_key,
            "bytes were altered in transit; this is meant to be a carry-across, not a re-encode"
        );
    }
}
