//! wasm-bindgen-test smoke tests for `wasm32-unknown-unknown`.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_namespace = ["module", "exports"], js_name = poseidon128Hash12Hex)]
extern "C" {
    fn poseidon128_hash_12_hex() -> Result<JsValue, JsValue>;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn poseidon_wasm_smoke() {
    let hex = poseidon128_hash_12_hex()
        .expect("poseidon128Hash12Hex")
        .as_string()
        .unwrap_or_default();
    assert_eq!(hex.len(), 16, "expected 16 hex chars (8+8 u32 limbs)");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
