mod common;

use lib_q_threshold_sig::{
    PROFILE_ENVELOPE_BUDGET_BYTES,
    aggregate,
    identify_abort,
    proactive_refresh,
    verify,
};

#[test]
fn threshold_sig_kat_vectors_cover_core_paths() {
    let (profile, keygen) = common::deterministic_keygen(0x42);
    let message = b"kat-sign-verify-3-of-5";
    let signers = common::select_signers(&keygen.secret_shares);
    let mut rng = common::deterministic_rng(0x43);
    let states = common::build_round_states(&profile, &signers, message, &mut rng);
    let commitments = states
        .iter()
        .map(|s| s.commitment.clone())
        .collect::<Vec<_>>();
    let partials = common::build_partials(
        &profile,
        &keygen.public_key,
        &signers,
        &states,
        &commitments,
        message,
    );

    let aggregate_out = aggregate(
        &profile,
        &keygen.public_key,
        message,
        &commitments,
        &partials,
    )
    .expect("aggregate");
    assert!(
        verify(
            &profile,
            &keygen.public_key,
            message,
            &aggregate_out.signature
        )
        .expect("verify")
    );
    assert!(aggregate_out.wire.len() <= PROFILE_ENVELOPE_BUDGET_BYTES);

    let mut tampered = partials.clone();
    tampered[1].z[0] ^= 0x80;
    let offenders = identify_abort(
        &profile,
        &keygen.public_key,
        message,
        &commitments,
        &tampered,
    )
    .expect("identify_abort");
    assert!(offenders.contains(&tampered[1].index));

    let mut refresh_rng = common::deterministic_rng(0x44);
    let refreshed =
        proactive_refresh(&profile, &keygen.secret_shares, &mut refresh_rng).expect("refresh");
    assert_ne!(
        keygen.secret_shares[0].share_bytes.as_slice(),
        refreshed[0].share_bytes.as_slice(),
    );
}
