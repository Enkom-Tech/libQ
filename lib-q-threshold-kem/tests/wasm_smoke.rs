//! wasm-bindgen-test smoke: threshold KEM JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use js_sys::{
    Array,
    Reflect,
    Uint8Array,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_threshold_kem::wasm::{
    threshold_kem_combine_decap_wasm,
    threshold_kem_encap_wasm,
    threshold_kem_keygen_shares_wasm,
    threshold_kem_partial_decap_wasm,
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
fn threshold_kem_round_trip_wasm() {
    let keygen_js = threshold_kem_keygen_shares_wasm(3, 5).expect("keygen");
    let public_key = get_prop(&keygen_js, "publicKey");
    let encap_js = threshold_kem_encap_wasm(public_key.clone()).expect("encap");
    let ciphertext_hex = get_prop(&encap_js, "ciphertextHex")
        .as_string()
        .expect("ciphertextHex");
    let shared_enc: Uint8Array = get_prop(&encap_js, "sharedSecret").into();

    let shares = Array::from(&get_prop(&keygen_js, "secretShares"));
    let mut partials = Vec::new();
    for i in 0..3 {
        let share = shares.get(i);
        let share_bytes: Uint8Array = get_prop(&share, "shareBytes").into();
        let partial_js = threshold_kem_partial_decap_wasm(
            &share_bytes.to_vec(),
            get_prop(&share, "index").as_f64().expect("index") as u8,
            get_prop(&share, "threshold").as_f64().expect("threshold") as u8,
            &get_prop(&share, "commitmentHex")
                .as_string()
                .expect("commitmentHex"),
            &ciphertext_hex,
        )
        .expect("partial");
        partials.push(
            serde_wasm_bindgen::from_value::<serde_json::Value>(partial_js).expect("partial json"),
        );
    }

    let combined = threshold_kem_combine_decap_wasm(
        &ciphertext_hex,
        to_value(&partials).expect("partials value"),
        public_key,
        3,
    )
    .expect("combine");
    assert_eq!(combined.to_vec(), shared_enc.to_vec());
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
