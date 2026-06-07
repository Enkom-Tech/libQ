mod common;

use lib_q_threshold_kem::{
    PARAMETER_SET_CANONICAL_BLOB_V1,
    WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
    combine_decap,
    encap,
    partial_decap,
    verify_share,
};

#[test]
fn threshold_kem_kat_vectors_cover_core_paths() {
    let (profile, keygen) = common::deterministic_keygen(0x42);
    assert_eq!(
        profile.parameter_set_digest,
        lib_q_sha3::sha3_256(PARAMETER_SET_CANONICAL_BLOB_V1.as_bytes())
    );

    let mut rng = common::deterministic_rng(0x43);
    let enc = encap(&profile, &keygen.public_key, &mut rng).expect("encap");
    assert!(enc.ciphertext.len() <= WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES);

    let partials = keygen
        .secret_shares
        .iter()
        .take(usize::from(common::THRESHOLD))
        .map(|share| partial_decap(share, &enc.ciphertext).expect("partial"))
        .collect::<Vec<_>>();
    for (partial, verifier) in partials
        .iter()
        .zip(keygen.public_key.share_verifiers.iter())
    {
        assert!(verify_share(verifier, &enc.ciphertext, partial));
    }

    let shared = combine_decap(
        &profile,
        &enc.ciphertext,
        &partials,
        &keygen.public_key.share_verifiers,
        common::THRESHOLD,
    )
    .expect("combine");
    assert_eq!(shared, enc.shared_secret);

    let mut malicious = partials.clone();
    malicious[0].share_bytes[0] ^= 0x80;
    assert!(!verify_share(
        &keygen.public_key.share_verifiers[0],
        &enc.ciphertext,
        &malicious[0]
    ));
    let err = combine_decap(
        &profile,
        &enc.ciphertext,
        &malicious,
        &keygen.public_key.share_verifiers,
        common::THRESHOLD,
    )
    .expect_err("malicious share must fail");
    assert!(matches!(
        err,
        lib_q_threshold_kem::ThresholdKemError::InvalidShareProof { .. }
    ));
}
