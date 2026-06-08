//! wasm-bindgen-test smoke: threshold signature JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use js_sys::{
    Array,
    Reflect,
    Uint8Array,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_threshold_sig::wasm::{
    threshold_sig_aggregate_wasm,
    threshold_sig_keygen_shares_wasm,
    threshold_sig_sign_round1_wasm,
    threshold_sig_sign_round2_wasm,
    threshold_sig_verify_wasm,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use serde_wasm_bindgen::to_value;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen::JsValue;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
fn get_prop(obj: &JsValue, key: &str) -> JsValue {
    Reflect::get(obj, &JsValue::from_str(key)).expect("property")
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn threshold_sig_sign_verify_wasm() {
    let message = b"wasm-threshold-sig-smoke";
    let keygen_js = threshold_sig_keygen_shares_wasm(3, 5).expect("keygen");
    let public_key = get_prop(&keygen_js, "publicKey");
    let shares = Array::from(&get_prop(&keygen_js, "secretShares"));

    let mut handles = Vec::new();
    let mut commitments = Vec::new();
    for i in 0..3 {
        let share = shares.get(i);
        let share_bytes: Uint8Array = get_prop(&share, "shareBytes").into();
        let bytes = share_bytes.to_vec();
        let index = get_prop(&share, "index").as_f64().expect("index") as u8;
        let threshold = get_prop(&share, "threshold").as_f64().expect("threshold") as u8;
        let handle =
            threshold_sig_sign_round1_wasm(&bytes, index, threshold, message).expect("round1");
        let commitment: serde_json::Value =
            serde_wasm_bindgen::from_value(handle.commitment_json().expect("commitment"))
                .expect("commitment json");
        commitments.push(commitment);
        handles.push((handle, bytes, index, threshold));
    }

    let commitments_value = to_value(&commitments).expect("commitments value");
    let mut partials = Vec::new();
    for (handle, bytes, index, threshold) in &handles {
        let partial_js = threshold_sig_sign_round2_wasm(
            handle,
            public_key.clone(),
            message,
            bytes,
            *index,
            *threshold,
            commitments_value.clone(),
        )
        .expect("round2");
        partials.push(
            serde_wasm_bindgen::from_value::<serde_json::Value>(partial_js).expect("partial"),
        );
    }

    let agg_js = threshold_sig_aggregate_wasm(
        public_key.clone(),
        message,
        commitments_value,
        to_value(&partials).expect("partials"),
    )
    .expect("aggregate");
    let signature = get_prop(&agg_js, "signature");
    assert!(threshold_sig_verify_wasm(public_key, message, signature).expect("verify"));
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
