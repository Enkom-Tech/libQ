//! wasm-bindgen-test smoke: threshold-KEM-lattice JS API on wasm32.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use lib_q_threshold_kem_lattice::wasm::{
    tkem_encaps_decaps_demo_wasm,
    tkem_setup_wasm,
};
use serde_wasm_bindgen::from_value;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn setup_and_encaps_decaps_smoke() {
    let setup: serde_json::Value = from_value(tkem_setup_wasm().expect("setup")).expect("json");
    assert_eq!(setup["profileId"].as_u64(), Some(1));

    let demo: serde_json::Value =
        from_value(tkem_encaps_decaps_demo_wasm(5, 3).expect("demo")).expect("json");
    assert_eq!(
        demo["match"].as_bool(),
        Some(true),
        "threshold decapsulation must recover the encapsulated secret"
    );
    assert!(
        demo["sharedSecretHex"]
            .as_str()
            .is_some_and(|h| h.len() == 64)
    );
}
