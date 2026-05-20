//! wasm-bindgen-test smoke tests for `wasm32-unknown-unknown`.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_namespace = ["module", "exports"], js_name = ringCoefficientCount)]
extern "C" {
    fn ring_coefficient_count() -> u32;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_namespace = ["module", "exports"], js_name = ringModulusQ)]
extern "C" {
    fn ring_modulus_q() -> u32;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn ring_wasm_smoke() {
    assert_eq!(ring_coefficient_count(), 256);
    assert_eq!(ring_modulus_q(), 8_380_417);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
