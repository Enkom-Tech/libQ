//! wasm-bindgen-test smoke: every `@lib-q/threshold-sig` binding must fail closed.
//!
//! **What this test used to do:** drive the full JS ceremony — `thresholdSigKeygenShares`,
//! two signing rounds, `thresholdSigAggregate` — and assert `thresholdSigVerify` returned
//! `true`. It therefore asserted that a JavaScript caller could obtain key material and get a
//! signature accepted, which is exactly what must no longer be possible.
//!
//! **What it does now:** asserts every export throws. The old keygen binding was the most
//! damaging path to the defect, since it handed each party's raw secret share to the host both
//! as `secretShares[].shareBytes` and, labelled as public data, as
//! `shareVerifiers[].verifyingKeyHex`.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_threshold_sig::wasm::{
    threshold_sig_aggregate_wasm,
    threshold_sig_decode_wire_v1_wasm,
    threshold_sig_encode_wire_v1_wasm,
    threshold_sig_identify_abort_wasm,
    threshold_sig_keygen_shares_wasm,
    threshold_sig_setup_wasm,
    threshold_sig_sign_round1_wasm,
    threshold_sig_sign_round2_wasm,
    threshold_sig_verify_wasm,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen::JsValue;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

/// No JavaScript caller can obtain key material, produce a signature, or get one accepted.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn every_wasm_export_fails_closed() {
    let message = b"wasm-threshold-sig-abuse-attempt";

    assert!(threshold_sig_setup_wasm().is_err(), "setup must throw");
    assert!(
        threshold_sig_keygen_shares_wasm(3, 5).is_err(),
        "keygen must throw and must never hand shares to JS",
    );
    assert!(
        threshold_sig_sign_round1_wasm(&[0u8; 32], 1, 3, message).is_err(),
        "round1 must throw",
    );
    assert!(
        threshold_sig_sign_round2_wasm(
            JsValue::NULL,
            JsValue::NULL,
            message,
            &[0u8; 32],
            1,
            3,
            JsValue::NULL,
        )
        .is_err(),
        "round2 must throw",
    );
    assert!(
        threshold_sig_aggregate_wasm(JsValue::NULL, message, JsValue::NULL, JsValue::NULL).is_err(),
        "aggregate must throw",
    );
    assert!(
        threshold_sig_verify_wasm(JsValue::NULL, message, JsValue::NULL).is_err(),
        "verify must throw — it must never return true",
    );
    assert!(
        threshold_sig_identify_abort_wasm(JsValue::NULL, message, JsValue::NULL, JsValue::NULL)
            .is_err(),
        "identify_abort must throw",
    );
    assert!(
        threshold_sig_encode_wire_v1_wasm("00", "00").is_err(),
        "encode wire must throw",
    );
    assert!(
        threshold_sig_decode_wire_v1_wasm(&[0u8; 8]).is_err(),
        "decode wire must throw",
    );
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
