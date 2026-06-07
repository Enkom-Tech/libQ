use lib_q_threshold_sig::{
    PROFILE_ENVELOPE_BUDGET_BYTES,
    PROFILE_ID_V1,
    ThresholdSigError,
    WIRE_BUDGET_THRESHOLD_SIG_BYTES,
    WIRE_VERSION_V1,
    decode_threshold_sig_wire_v1,
    encode_threshold_sig_wire_v1,
    setup,
};

#[test]
fn threshold_sig_wire_budget_gates() {
    let profile = setup();
    let oversized_sig = vec![0u8; WIRE_BUDGET_THRESHOLD_SIG_BYTES];
    let err = encode_threshold_sig_wire_v1(&profile, &oversized_sig, &[])
        .expect_err("oversized signature should fail");
    assert!(matches!(err, ThresholdSigError::BudgetExceeded { .. }));

    let mut wire = vec![WIRE_VERSION_V1, PROFILE_ID_V1];
    wire.extend_from_slice(&4u16.to_le_bytes());
    wire.extend_from_slice(&[0u8; 4]);
    wire.extend_from_slice(&0u16.to_le_bytes());
    wire.extend_from_slice(&vec![0u8; WIRE_BUDGET_THRESHOLD_SIG_BYTES]);
    let err =
        decode_threshold_sig_wire_v1(&profile, &wire).expect_err("oversized wire should fail");
    assert!(matches!(err, ThresholdSigError::BudgetExceeded { .. }));
}

#[test]
fn threshold_sig_profile_envelope_lane() {
    let profile = setup();
    let sig = vec![0u8; 96];
    let meta = vec![0u8; 128];
    let wire = encode_threshold_sig_wire_v1(&profile, &sig, &meta).expect("small envelope");
    assert!(wire.len() <= PROFILE_ENVELOPE_BUDGET_BYTES);
}
