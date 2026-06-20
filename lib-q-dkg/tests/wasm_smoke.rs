//! wasm-bindgen-test smoke: DKG JS API on wasm32.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use lib_q_dkg::wasm::{
    dkg_decode_round1_wasm,
    dkg_keygen_wasm,
    dkg_setup_wasm,
};
use serde_wasm_bindgen::from_value;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn dkg_setup_and_keygen_smoke() {
    let setup_js = dkg_setup_wasm().expect("setup");
    let setup: serde_json::Value = from_value(setup_js).expect("setup json");
    assert_eq!(setup["profileId"].as_u64(), Some(1));

    let kg_js = dkg_keygen_wasm(5, 3).expect("keygen");
    let kg: serde_json::Value = from_value(kg_js).expect("keygen json");
    assert_eq!(kg["publicKey"]["threshold"].as_u64(), Some(3));
    assert!(
        kg["publicKey"]["groupKeyHex"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "group key must be present",
    );
    assert_eq!(
        kg["secretShares"].as_array().map(|a| a.len()),
        Some(5),
        "must produce one share per party",
    );
}

#[wasm_bindgen_test]
fn dkg_decode_rejects_garbage() {
    // Random bytes must be rejected (Err → JsValue), not panic.
    assert!(dkg_decode_round1_wasm(&[0u8; 8]).is_err());
}
