use lib_q_threshold_kem::{
    ThresholdKemError,
    WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES,
    WIRE_VERSION_V1,
    decode_threshold_kem_wire_v1,
    encode_threshold_kem_wire_v1,
    setup,
};

#[test]
fn threshold_kem_budget_gates() {
    let profile = setup();
    let oversized = vec![0u8; WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES + 1];
    let err =
        encode_threshold_kem_wire_v1(&profile, &oversized, &[]).expect_err("oversized encode");
    assert!(matches!(
        err,
        ThresholdKemError::CiphertextBudgetExceeded { .. }
    ));

    let mut wire = vec![WIRE_VERSION_V1, profile.id];
    wire.extend_from_slice(
        &(u32::try_from(WIRE_BUDGET_TKEM_CIPHERTEXT_BYTES + 1).expect("u32")).to_le_bytes(),
    );
    wire.extend_from_slice(&0u16.to_le_bytes());
    let err = decode_threshold_kem_wire_v1(&profile, &wire).expect_err("oversized decode");
    assert!(matches!(
        err,
        ThresholdKemError::CiphertextBudgetExceeded { .. }
    ));
}
