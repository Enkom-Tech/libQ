//! Correctness of the lattice threshold KEM: trusted-dealer keygen, dealerless DKG keygen, the
//! distributed share-private (flooded) path, the FO⊥ rejection, and negative cases.
//!
//! Run in release (the shared `lib-q-dkg` lattice is slow in debug):
//! `cargo test -p lib-q-threshold-kem-lattice --release`.

use lib_q_dkg::lattice::ring::Rq;
use lib_q_random::new_deterministic_rng;
use lib_q_threshold_kem_lattice::threshold::{
    DecapBudget,
    ZeroShareSeeds,
    partial_decap_masked,
    partial_decap_masked_budgeted,
};
use lib_q_threshold_kem_lattice::{
    Ciphertext,
    MALFORMED_PROBE_SAFE_DECAPS,
    PartialDecap,
    SecretShare,
    ThresholdKemError,
    ThresholdKemLatticePublicKey,
    combine,
    decapsulate_reference,
    encapsulate,
    keygen_shares,
    partial_decap,
    public_key_from_dkg,
    setup,
    share_from_dkg,
};
use zeroize::Zeroizing;

const THRESHOLD: u8 = 3;
const PARTIES: u8 = 5;

#[test]
fn trusted_dealer_encap_decap_roundtrip() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x11u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");

    let (ss_encap, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    // Any threshold-sized subset recovers the same shared secret.
    let subset = &keygen.secret_shares[1..1 + usize::from(THRESHOLD)];
    let ss_decap = decapsulate_reference(&keygen.public_key, subset, &ct).expect("decap");
    assert_eq!(ss_encap, ss_decap, "reference decap must match encap");

    // A different subset also works and agrees.
    let subset2 = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let ss_decap2 = decapsulate_reference(&keygen.public_key, subset2, &ct).expect("decap2");
    assert_eq!(ss_encap, ss_decap2, "second subset must match");
}

#[test]
fn ciphertext_serialization_roundtrips() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x22u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), Ciphertext::BYTES);
    let ct2 = Ciphertext::from_bytes(&bytes).expect("decode");
    assert_eq!(ct, ct2);
}

#[test]
fn encapsulation_is_deterministic_in_mu() {
    // The FO⊥ check requires Enc(pk, μ) to be a bit-exact function of (pk, μ).
    let profile = setup();
    let mut rng = new_deterministic_rng([0x77u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let t0 = keygen.public_key.t0().expect("t0");
    let mu = [0xA5u8; 32];
    let ct1 = lib_q_threshold_kem_lattice::kem::encapsulate_derand(&t0, &mu);
    let ct2 = lib_q_threshold_kem_lattice::kem::encapsulate_derand(&t0, &mu);
    assert_eq!(ct1, ct2, "derandomized encryption must be deterministic");
    let mu2 = [0xA6u8; 32];
    assert_ne!(
        lib_q_threshold_kem_lattice::kem::encapsulate_derand(&t0, &mu2),
        ct1,
        "different messages must give different ciphertexts"
    );
}

#[test]
fn fo_rejects_tampered_ciphertext() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x88u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    // Flip one coefficient of v: decode may still succeed, but the FO re-encryption must reject.
    let mut bytes = ct.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let Ok(mauled) = Ciphertext::from_bytes(&bytes) else {
        return; // flipped byte made a coefficient non-canonical: rejected even earlier — fine
    };

    let subset = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let err = decapsulate_reference(&keygen.public_key, subset, &mauled)
        .expect_err("mauled ciphertext must be rejected");
    assert_eq!(err, ThresholdKemError::InvalidCiphertext);
}

#[test]
fn distributed_masked_path_matches_reference() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x33u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (ss_encap, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    let seeds = ZeroShareSeeds::setup(PARTIES, &mut rng);
    // Pick a threshold subset by index.
    let chosen = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();

    // Flooded + zero-share-masked partials must still combine exactly (the flooding is inside the
    // decode margin) and pass the FO check.
    let partials: Vec<_> = chosen
        .iter()
        .map(|s| partial_decap_masked(s, &subset, &ct, &seeds, &mut rng).expect("masked partial"))
        .collect();
    let ss_decap = combine(&keygen.public_key, &partials, &ct).expect("combine");
    assert_eq!(
        ss_encap, ss_decap,
        "masked+flooded distributed decap must match encap"
    );
}

#[test]
fn from_pairwise_seeds_mask_and_cancel() {
    // The PRODUCTION seed source: seeds supplied via `from_pairwise` (externally derived pairwise
    // secrets) must produce the same cancel-to-zero masking as the random `setup` helper.
    let profile = setup();
    let mut rng = new_deterministic_rng([0x9Au8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (ss_encap, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    // Canonical (i<j) entries with distinct deterministic seed bytes, built via the constructor.
    let mut entries = Vec::new();
    for i in 1..=PARTIES {
        for j in (i + 1)..=PARTIES {
            let mut s = [0u8; 32];
            s[0] = i;
            s[1] = j;
            s[2] = 0xA5;
            entries.push((i, j, s));
        }
    }
    let seeds = ZeroShareSeeds::from_pairwise(entries).expect("from_pairwise");

    let chosen = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();
    let partials: Vec<_> = chosen
        .iter()
        .map(|s| partial_decap_masked(s, &subset, &ct, &seeds, &mut rng).expect("masked partial"))
        .collect();
    let ss_decap = combine(&keygen.public_key, &partials, &ct).expect("combine");
    assert_eq!(
        ss_encap, ss_decap,
        "from_pairwise seeds must mask-and-cancel exactly like setup"
    );
}

#[test]
fn partial_decap_serialization_roundtrips() {
    use lib_q_threshold_kem_lattice::PartialDecap;
    let profile = setup();
    let mut rng = new_deterministic_rng([0xB7u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (ss_encap, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    let seeds = ZeroShareSeeds::setup(PARTIES, &mut rng);
    let chosen = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();

    // Each masked partial survives a wire round-trip and the set still combines to the secret.
    let partials: Vec<_> = chosen
        .iter()
        .map(|s| {
            let p = partial_decap_masked(s, &subset, &ct, &seeds, &mut rng).expect("masked partial");
            let bytes = p.to_bytes();
            assert_eq!(bytes.len(), PartialDecap::BYTES);
            PartialDecap::from_bytes(&bytes).expect("decode")
        })
        .collect();
    let ss_decap = combine(&keygen.public_key, &partials, &ct).expect("combine");
    assert_eq!(ss_encap, ss_decap, "wire-encoded masked partials combine to the secret");

    // A wrong length is rejected.
    assert_eq!(
        PartialDecap::from_bytes(&[0u8; 3]).err(),
        Some(lib_q_threshold_kem_lattice::ThresholdKemError::EncodingPartial)
    );
}

#[test]
fn from_pairwise_rejects_non_canonical_entries() {
    use lib_q_threshold_kem_lattice::ThresholdKemError::InvalidSeedEntry;
    // Zero party index (either position).
    assert_eq!(ZeroShareSeeds::from_pairwise(vec![(0, 1, [0u8; 32])]).err(), Some(InvalidSeedEntry));
    assert_eq!(ZeroShareSeeds::from_pairwise(vec![(1, 0, [0u8; 32])]).err(), Some(InvalidSeedEntry));
    // Non-canonical ordering (entries must be i < j).
    assert_eq!(ZeroShareSeeds::from_pairwise(vec![(3, 3, [0u8; 32])]).err(), Some(InvalidSeedEntry));
    assert_eq!(ZeroShareSeeds::from_pairwise(vec![(4, 2, [0u8; 32])]).err(), Some(InvalidSeedEntry));
    // Duplicate unordered pair.
    assert_eq!(
        ZeroShareSeeds::from_pairwise(vec![(1, 2, [7u8; 32]), (1, 2, [8u8; 32])]).err(),
        Some(InvalidSeedEntry)
    );
    // A valid canonical set is accepted.
    assert!(
        ZeroShareSeeds::from_pairwise(vec![(1, 2, [1u8; 32]), (1, 3, [2u8; 32]), (2, 3, [3u8; 32])])
            .is_ok()
    );
}

#[test]
fn decap_budget_enforces_per_key_cap() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x5Bu8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (ss_encap, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");
    let seeds = ZeroShareSeeds::setup(PARTIES, &mut rng);
    let chosen = &keygen.secret_shares[..usize::from(THRESHOLD)];
    let subset: Vec<u8> = chosen.iter().map(|s| s.index).collect();

    // A budget capped at exactly THRESHOLD emits exactly enough partials for one combine, then
    // refuses — and the budgeted partials still combine to the correct secret (budgeting is a rate
    // gate only; it does not perturb the value).
    let mut budget = DecapBudget::new(u64::from(THRESHOLD));
    assert_eq!(budget.remaining(), u64::from(THRESHOLD));
    let partials: Vec<_> = chosen
        .iter()
        .map(|s| {
            partial_decap_masked_budgeted(s, &subset, &ct, &seeds, &mut rng, &mut budget)
                .expect("budgeted partial within cap")
        })
        .collect();
    assert_eq!(budget.remaining(), 0);
    assert_eq!(budget.used(), u64::from(THRESHOLD));
    let ss = combine(&keygen.public_key, &partials, &ct).expect("combine");
    assert_eq!(ss_encap, ss, "budgeted partials must combine correctly");

    // One more partial is refused: the key must be rotated instead.
    let err =
        partial_decap_masked_budgeted(&chosen[0], &subset, &ct, &seeds, &mut rng, &mut budget)
            .expect_err("budget must be exhausted");
    assert_eq!(err, ThresholdKemError::BudgetExhausted);

    // A validation failure (bad subset: a zero index) does NOT consume a slot.
    let mut budget2 = DecapBudget::new(1);
    let bad_subset = vec![0u8, chosen[1].index];
    let err =
        partial_decap_masked_budgeted(&chosen[0], &bad_subset, &ct, &seeds, &mut rng, &mut budget2)
            .expect_err("bad subset must be rejected");
    assert_eq!(err, ThresholdKemError::InvalidSubset);
    assert_eq!(
        budget2.remaining(),
        1,
        "rejected call must not consume budget"
    );

    // The named regime helpers expose the documented caps.
    assert_eq!(
        DecapBudget::untrusted().remaining(),
        MALFORMED_PROBE_SAFE_DECAPS
    );
    assert!(DecapBudget::authenticated().remaining() >= MALFORMED_PROBE_SAFE_DECAPS);
}

#[test]
fn dealerless_dkg_key_encaps_and_decaps() {
    // The load-bearing interop test: keys from lib-q-dkg's dealerless DKG drive the KEM directly,
    // with no trusted dealer (the analogue of raccoon's `dealerless_dkg_key_signs_and_verifies`).
    let dkg_profile = lib_q_dkg::setup();
    let mut rng = new_deterministic_rng([0x44u8; 32]);
    let out = lib_q_dkg::dkg_run_honest(&dkg_profile, PARTIES, THRESHOLD, &mut rng).expect("dkg");

    let pk = public_key_from_dkg(&out.public_key).expect("pk from dkg");
    let shares: Vec<_> = out.secret_shares.iter().map(share_from_dkg).collect();

    let (ss_encap, ct) = encapsulate(&pk, &mut rng).expect("encap");
    let subset = &shares[..usize::from(THRESHOLD)];
    let ss_decap = decapsulate_reference(&pk, subset, &ct).expect("decap");
    assert_eq!(
        ss_encap, ss_decap,
        "dealerless DKG key must decapsulate correctly"
    );
}

#[test]
fn wrong_subset_size_fails_to_recover() {
    // Fewer than `threshold` shares cannot interpolate ⟨r, p⟩. The API rejects the subset up
    // front (InvalidSubset) rather than wasting an FO cycle on guaranteed garbage — the FO
    // backstop for a *wrong-valued* aggregate is exercised by `corrupted_partial_rejected_by_fo`.
    let profile = setup();
    let mut rng = new_deterministic_rng([0x55u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    let too_few = &keygen.secret_shares[..usize::from(THRESHOLD) - 1];
    let err = decapsulate_reference(&keygen.public_key, too_few, &ct)
        .expect_err("sub-threshold decap must be rejected");
    assert_eq!(err, ThresholdKemError::InvalidSubset);

    // Threshold-sized partial sets are also enforced at combine itself.
    let subset: Vec<u8> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| s.index)
        .collect();
    let partials: Vec<_> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| partial_decap(s, &subset, &ct).expect("partial"))
        .collect();
    let err = combine(&keygen.public_key, &partials[..1], &ct)
        .expect_err("sub-threshold combine must be rejected");
    assert_eq!(err, ThresholdKemError::InvalidSubset);
}

#[test]
fn corrupted_partial_rejected_by_fo() {
    // A tampered partial value yields the wrong aggregate ⟨r, p⟩; the decoded message is garbage
    // and the FO re-encryption check must reject (a wrong aggregate can never silently return a
    // wrong secret) — the cryptographic backstop behind the structural subset checks.
    let profile = setup();
    let mut rng = new_deterministic_rng([0x99u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    let subset: Vec<u8> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| s.index)
        .collect();
    let mut partials: Vec<_> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| partial_decap(s, &subset, &ct).expect("partial"))
        .collect();
    partials[0].value = partials[1].value.clone(); // corrupt one contribution
    let err = combine(&keygen.public_key, &partials, &ct)
        .expect_err("corrupted partial must be rejected by the FO check");
    assert_eq!(err, ThresholdKemError::InvalidCiphertext);
}

#[test]
fn deserialization_rejects_invalid_inputs() {
    // Ciphertext: wrong lengths and a non-canonical (≥ q) coefficient must all fail closed.
    assert_eq!(
        Ciphertext::from_bytes(&[]).unwrap_err(),
        ThresholdKemError::EncodingCiphertext
    );
    assert_eq!(
        Ciphertext::from_bytes(&vec![0u8; Ciphertext::BYTES - 1]).unwrap_err(),
        ThresholdKemError::EncodingCiphertext
    );
    assert_eq!(
        Ciphertext::from_bytes(&vec![0u8; Ciphertext::BYTES + 1]).unwrap_err(),
        ThresholdKemError::EncodingCiphertext
    );
    let mut bytes = vec![0u8; Ciphertext::BYTES];
    bytes[..6].fill(0xFF); // first coefficient = 2^48 - 1 ≥ q: non-canonical
    assert_eq!(
        Ciphertext::from_bytes(&bytes).unwrap_err(),
        ThresholdKemError::EncodingCiphertext
    );
    // An all-zero buffer is canonical and must decode.
    let zero_ct = Ciphertext::from_bytes(&vec![0u8; Ciphertext::BYTES]).expect("zero ct decodes");

    // Public key blob: wrong length and non-canonical coefficient.
    const T0_BYTES: usize = 6 * 6144; // MU · RQ_BYTES
    let bad_len = ThresholdKemLatticePublicKey {
        threshold: THRESHOLD,
        t0_bytes: vec![0u8; T0_BYTES - 1],
    };
    assert_eq!(
        bad_len.t0().unwrap_err(),
        ThresholdKemError::EncodingPublicKey
    );
    let mut t0_bytes = vec![0u8; T0_BYTES];
    t0_bytes[..6].fill(0xFF);
    let bad_coeff = ThresholdKemLatticePublicKey {
        threshold: THRESHOLD,
        t0_bytes,
    };
    assert_eq!(
        bad_coeff.t0().unwrap_err(),
        ThresholdKemError::EncodingPublicKey
    );

    // Share blob: wrong length surfaces as EncodingShare from the partial-decap entry point.
    let bad_share = SecretShare {
        index: 1,
        threshold: THRESHOLD,
        share_bytes: Zeroizing::new(vec![0u8; 10]),
    };
    assert_eq!(
        partial_decap(&bad_share, &[1, 2, 3], &zero_ct).unwrap_err(),
        ThresholdKemError::EncodingShare
    );
}

#[test]
fn structural_and_subset_validation_rejects_bad_inputs() {
    let zero_ct = Ciphertext::from_bytes(&vec![0u8; Ciphertext::BYTES]).expect("zero ct");
    // share_bytes is never decoded on these paths — validation fires first.
    let share = |index: u8| SecretShare {
        index,
        threshold: THRESHOLD,
        share_bytes: Zeroizing::new(Vec::new()),
    };

    // Share index 0 (the Shamir evaluation point of the secret itself) is rejected.
    let err = partial_decap(&share(0), &[0, 2, 3], &zero_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::InvalidSubset);
    // Zero entries anywhere in the subset are rejected.
    let err = partial_decap(&share(2), &[0, 2, 3], &zero_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::InvalidSubset);
    // Duplicate subset entries are rejected.
    let err = partial_decap(&share(2), &[2, 3, 3], &zero_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::InvalidSubset);
    // Sub-threshold subsets are rejected.
    let err = partial_decap(&share(1), &[1, 2], &zero_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::InvalidSubset);
    // The caller's index must appear in the subset.
    let err = partial_decap(&share(4), &[1, 2, 3], &zero_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::InvalidSubset);

    // A hand-built ciphertext with the wrong `p` element count fails closed everywhere —
    // the `pub` fields cannot bypass the structural guard.
    let short_ct = Ciphertext {
        p: Vec::new(),
        v: Rq::zero(),
    };
    let err = partial_decap(&share(1), &[1, 2, 3], &short_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::EncodingCiphertext);
    let partials: Vec<PartialDecap> = (1..=THRESHOLD)
        .map(|index| PartialDecap {
            index,
            value: Rq::zero(),
        })
        .collect();
    let pk = ThresholdKemLatticePublicKey {
        threshold: THRESHOLD,
        t0_bytes: vec![0u8; 6 * 6144],
    };
    let err = combine(&pk, &partials, &short_ct).unwrap_err();
    assert_eq!(err, ThresholdKemError::EncodingCiphertext);
}

#[test]
fn duplicate_index_rejected() {
    let profile = setup();
    let mut rng = new_deterministic_rng([0x66u8; 32]);
    let keygen = keygen_shares(&profile, THRESHOLD, PARTIES, &mut rng).expect("keygen");
    let (_ss, ct) = encapsulate(&keygen.public_key, &mut rng).expect("encap");

    let subset: Vec<u8> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| s.index)
        .collect();
    let mut partials: Vec<_> = keygen.secret_shares[..usize::from(THRESHOLD)]
        .iter()
        .map(|s| partial_decap(s, &subset, &ct).expect("partial"))
        .collect();
    partials.push(partials[0].clone()); // inject a duplicate
    assert!(
        combine(&keygen.public_key, &partials, &ct).is_err(),
        "duplicate index must be rejected"
    );
}
