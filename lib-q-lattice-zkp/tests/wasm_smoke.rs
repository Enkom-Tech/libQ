//! wasm-bindgen-test smoke tests for `wasm32-unknown-unknown`.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn lattice_zkp_wasm_smoke() {
    assert_eq!(2_u8.saturating_add(2), 4);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
