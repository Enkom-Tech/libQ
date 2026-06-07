mod common;

use lib_q_threshold_sig::{
    aggregate,
    decode_signature,
    decode_threshold_sig_wire_v1,
};

#[test]
fn wire_roundtrip() {
    let (profile, keygen) = common::deterministic_keygen(0x11);
    let message = b"threshold-sig-wire-roundtrip";
    let signers = common::select_signers(&keygen.secret_shares);
    let mut rng = common::deterministic_rng(0x22);
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

    let decoded = decode_threshold_sig_wire_v1(&profile, &aggregate_out.wire).expect("decode");
    assert_eq!(decoded.signature, aggregate_out.signature_bytes);
    assert_eq!(
        decode_signature(&decoded.signature).expect("sig"),
        aggregate_out.signature
    );
}
