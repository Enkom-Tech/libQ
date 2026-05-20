//! wasm-bindgen-test smoke tests for `wasm32-unknown-unknown`.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ring::wasm::{
    ring_coefficient_count,
    ring_modulus_q,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ring_wasm_smoke() {
    assert_eq!(ring_coefficient_count(), 256);
    assert_eq!(ring_modulus_q(), 8_380_417);
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
