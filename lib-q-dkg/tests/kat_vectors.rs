//! Core-path coverage for the binding dealerless DKG.
//!
//! Run with `--release`: each share carries a Fiat–Shamir proof (Gaussian masking over `N = 1024`),
//! which is far too slow in an unoptimized build. CI runs this crate only under `release-ci`.

mod common;

use common::{
    PARTIES,
    THRESHOLD,
    det_rng,
};
use lib_q_dkg::lattice::bdlop::pow_mod_q;
use lib_q_dkg::lattice::ring::{
    Q,
    Rq,
    centered_coeffs,
    ring_add,
    scalar_mul,
};
use lib_q_dkg::{
    dkg_assemble_vk_set,
    dkg_build_complaint,
    dkg_check_complaint,
    dkg_eval_share,
    dkg_finalize_share,
    dkg_reshare,
    dkg_round1_commit,
    dkg_run_honest,
    dkg_verify_share,
    lagrange_coeff_at_zero,
    setup,
    signing_share_commitment,
};

#[test]
fn round1_shares_verify_and_tamper_is_caught() {
    let profile = setup();
    let mut rng = det_rng(0x11);
    let (poly, comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 1, &mut rng).expect("round1");

    // Every honest recipient's share verifies against the public commitments.
    for recipient in 1..=PARTIES {
        let share = dkg_eval_share(&poly, recipient, &mut rng).expect("eval");
        assert!(
            dkg_verify_share(&comms, 1, recipient, &share),
            "honest share must verify for recipient {recipient}",
        );
    }

    // A tampered share value fails verification, and a complaint built from it is publicly upheld.
    let mut bad = dkg_eval_share(&poly, 2, &mut rng).expect("eval");
    bad.value.coeffs[0] ^= 1;
    assert!(
        !dkg_verify_share(&comms, 1, 2, &bad),
        "tampered share must fail"
    );
    let complaint = dkg_build_complaint(1, 2, &bad);
    assert!(
        dkg_check_complaint(&comms, &complaint),
        "complaint over an inconsistent share must be upheld",
    );

    // A complaint over an honest share is NOT upheld.
    let good = dkg_eval_share(&poly, 2, &mut rng).expect("eval");
    let bogus = dkg_build_complaint(1, 2, &good);
    assert!(
        !dkg_check_complaint(&comms, &bogus),
        "complaint over a consistent share must be rejected",
    );
}

/// Adaptive-dealer kernel injection. Against a bare-Ajtai commitment a dealer can add a non-short
/// `κ` (`A·κ ≡ 0`) to the victim's share, keeping the commitment image while corrupting the value.
/// With BDLOP the share value sits in the clear (`t1`) and is pinned by a proof of correct sharing,
/// so **any** change to the delivered value is rejected — there is no kernel that preserves the
/// commitment while moving the cleartext share.
#[test]
fn kernel_injection_is_rejected_by_binding_proof() {
    let profile = setup();
    let mut rng = det_rng(0x99);
    let (poly, comms) =
        dkg_round1_commit(&profile, PARTIES, THRESHOLD, 1, &mut rng).expect("round1");

    let recipient = 2u8;
    let honest = dkg_eval_share(&poly, recipient, &mut rng).expect("eval");
    assert!(
        dkg_verify_share(&comms, 1, recipient, &honest),
        "honest share must verify"
    );

    // Inject an arbitrary non-zero offset δ into the share value, keeping the (now stale) proof.
    let mut forged = honest.clone();
    forged.value.coeffs[3] = (forged.value.coeffs[3] + 123_456) % Q;
    assert_ne!(
        forged.value, honest.value,
        "injection must change the share value"
    );
    assert!(
        !dkg_verify_share(&comms, 1, recipient, &forged),
        "kernel-injected share must be rejected by the binding proof",
    );

    // Re-randomizing the disclosed opening randomness to mask the change is also caught (the proof is
    // bound to the value, and the homomorphic opening no longer matches).
    let mut forged2 = honest.clone();
    forged2.value.coeffs[7] = (forged2.value.coeffs[7] + 1) % Q;
    forged2.rand[0].coeffs[0] = (forged2.rand[0].coeffs[0] + 999) % Q;
    assert!(
        !dkg_verify_share(&comms, 1, recipient, &forged2),
        "value+randomness tamper must be rejected",
    );
}

#[test]
fn honest_run_shares_match_verification_keys() {
    let profile = setup();
    let mut rng = det_rng(0x42);
    let kg = dkg_run_honest(&profile, PARTIES, THRESHOLD, &mut rng).expect("dkg");

    assert_eq!(kg.secret_shares.len(), usize::from(PARTIES));
    assert_eq!(kg.public_key.share_verifiers.len(), usize::from(PARTIES));
    assert_eq!(kg.public_key.threshold, THRESHOLD);

    // commit(value; rand) recomputed from the finalized share must equal the published vk.
    for share in &kg.secret_shares {
        let recomputed = signing_share_commitment(share).expect("commit share");
        let vk = &kg.public_key.share_verifiers[usize::from(share.index - 1)];
        assert_eq!(vk.index, share.index);
        assert_eq!(recomputed, vk.verifying_key, "share {} vs vk", share.index);
    }
}

/// `Σ_{i∈subset} λ_i · F(i)` recovers `F(0)` for the degree-`t-1` finalized sharing polynomial.
fn interpolate_zero(subset: &[u8], values: &[(u8, Rq)]) -> Rq {
    let mut acc = Rq::zero();
    for &i in subset {
        let lam = lagrange_coeff_at_zero(subset, i).expect("lagrange");
        let v = &values.iter().find(|(idx, _)| *idx == i).expect("value").1;
        acc = ring_add(&acc, &scalar_mul(v, lam));
    }
    acc
}

/// Resharing preserves the group **secret** and produces **binding-verifiable** sub-shares.
#[test]
fn reshare_is_binding_and_preserves_secret() {
    let profile = setup();
    let mut rng = det_rng(0x66);

    // Every party deals; collect polys + commitments.
    let mut polys = Vec::new();
    let mut all_comms = Vec::new();
    for party in 1..=PARTIES {
        let (poly, comms) =
            dkg_round1_commit(&profile, PARTIES, THRESHOLD, party, &mut rng).expect("r1");
        polys.push(poly);
        all_comms.push(comms);
    }

    // Finalized share VALUE for each party = Σ_dealer f_dealer(i).
    let subset = [1u8, 2, 3];
    let mut finalized_values: Vec<(u8, Rq)> = Vec::new();
    let mut signing_shares = Vec::new();
    for i in 1..=PARTIES {
        let mut received = Vec::new();
        let mut val = Rq::zero();
        for poly in &polys {
            let s = dkg_eval_share(poly, i, &mut rng).expect("eval");
            val = ring_add(&val, &s.value);
            received.push(s);
        }
        finalized_values.push((i, val));
        signing_shares.push(dkg_finalize_share(&received).expect("finalize"));
    }
    let old_secret = interpolate_zero(&subset, &finalized_values);

    // A threshold subset reshares to a fresh committee.
    let new_committee = [1u8, 2, 3, 4, 5];
    let new_t = 3u8;
    // new_value[m] = Σ_{i∈subset} g_i(m), where g_i = i's resharing polynomial.
    let mut new_values: Vec<(u8, Rq)> = new_committee.iter().map(|&m| (m, Rq::zero())).collect();
    for &i in &subset {
        let share = &signing_shares[usize::from(i - 1)];
        let lambda = lagrange_coeff_at_zero(&subset, i).expect("lagrange");
        let round1 = dkg_reshare(share, lambda, &new_committee, new_t, &mut rng).expect("reshare");
        for sub in &round1.shares {
            // Reshared sub-shares are binding-verifiable against the resharing commitments.
            assert!(
                dkg_verify_share(&round1.commitments, i, sub.recipient, sub),
                "reshared sub-share must verify (binding resharing)",
            );
            let slot = new_values
                .iter_mut()
                .find(|(m, _)| *m == sub.recipient)
                .unwrap();
            slot.1 = ring_add(&slot.1, &sub.value);
        }
    }

    // The new committee's finalized shares lie on a polynomial with the SAME constant term.
    let new_secret = interpolate_zero(&subset, &new_values);
    assert_eq!(
        centered_coeffs(&old_secret),
        centered_coeffs(&new_secret),
        "resharing must preserve the group secret",
    );
}

/// Sanity: the homomorphic VK set is well-formed and `pow_mod_q` matches a direct evaluation.
#[test]
fn vk_set_is_homomorphic() {
    let profile = setup();
    let mut rng = det_rng(0x55);
    let (_p, c1) = dkg_round1_commit(&profile, PARTIES, THRESHOLD, 1, &mut rng).expect("r1");
    let (_p2, c2) = dkg_round1_commit(&profile, PARTIES, THRESHOLD, 2, &mut rng).expect("r1");
    let vk = dkg_assemble_vk_set(&[c1, c2], PARTIES).expect("vk");
    assert_eq!(vk.share_verifiers.len(), usize::from(PARTIES));
    assert_eq!(pow_mod_q(3, 2), 9);
}
