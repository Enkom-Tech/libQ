use lib_q_double_kem::{
    BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
    MAUL_HINT_BYTES,
    MAUL_WIRE_BODY_BYTES,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
};

#[test]
fn budget_constants_match_profile() {
    assert_eq!(WIRE_BUDGET_MAUL_ENCAP_BYTES, 1260);
    assert_eq!(BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES, 2176);
    assert_eq!(
        MAUL_HINT_BYTES + MAUL_WIRE_BODY_BYTES,
        WIRE_BUDGET_MAUL_ENCAP_BYTES
    );
    assert_eq!(MAUL_HINT_BYTES, 172);
    assert_eq!(MAUL_WIRE_BODY_BYTES, 1088);
}

#[test]
fn savings_gate_is_at_least_forty_percent() {
    let saved = BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES - WIRE_BUDGET_MAUL_ENCAP_BYTES;
    let savings_percent =
        (saved as f64) * 100.0 / (BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES as f64);
    assert!(
        savings_percent >= 40.0,
        "wire savings dropped below threshold: {savings_percent:.4}%"
    );
}
