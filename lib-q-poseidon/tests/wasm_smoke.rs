//! wasm-bindgen-test smoke tests for `wasm32-unknown-unknown`.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_poseidon::wasm::poseidon128_hash_12_hex;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn poseidon_wasm_smoke() {
    let hex = poseidon128_hash_12_hex()
        .expect("poseidon128Hash12Hex")
        .as_string()
        .unwrap_or_default();
    assert_eq!(hex.len(), 16, "expected 16 hex chars (8+8 u32 limbs)");
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
