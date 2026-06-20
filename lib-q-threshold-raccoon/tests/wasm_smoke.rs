//! wasm-bindgen-test smoke: threshold-raccoon JS API on wasm32.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use lib_q_threshold_raccoon::wasm::{
    raccoon_setup_wasm,
    raccoon_sign_verify_demo_wasm,
};
use serde_wasm_bindgen::from_value;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn setup_and_sign_verify_smoke() {
    let setup: serde_json::Value = from_value(raccoon_setup_wasm().expect("setup")).expect("json");
    assert_eq!(setup["profileId"].as_u64(), Some(1));

    let demo: serde_json::Value =
        from_value(raccoon_sign_verify_demo_wasm(5, 3, b"wasm-smoke").expect("demo"))
            .expect("json");
    assert_eq!(
        demo["verified"].as_bool(),
        Some(true),
        "demo signature must verify"
    );
    assert!(demo["signatureHex"].as_str().is_some_and(|h| !h.is_empty()));
}
