//! wasm-bindgen-test smoke: toy FHE JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use js_sys::Int32Array;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_fhe::wasm::{
    fhe_decrypt_wasm,
    fhe_encrypt_wasm,
    fhe_eval_wasm,
    fhe_keygen_wasm,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use serde_json::json;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use serde_wasm_bindgen::to_value;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn fhe_encrypt_decrypt_wasm() {
    let _keygen = fhe_keygen_wasm(42, 8, 97).expect("keygen");
    let plain = Int32Array::new_with_length(4);
    plain.copy_from(&[3i32, 5, 7, 11]);
    let ct = fhe_encrypt_wasm(42, 8, 97, &plain, 1).expect("encrypt");
    let decrypted = fhe_decrypt_wasm(42, 8, 97, ct).expect("decrypt");
    assert_eq!(decrypted.to_vec(), vec![3, 5, 7, 11]);
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn fhe_eval_add_constant_wasm() {
    let plain = Int32Array::new_with_length(2);
    plain.copy_from(&[1i32, 2]);
    let ct = fhe_encrypt_wasm(7, 4, 101, &plain, 9).expect("encrypt");
    let op = to_value(&json!({ "op": "addConstant", "value": 5 })).expect("op json");
    let ct2 = fhe_eval_wasm(ct, op).expect("eval");
    let decrypted = fhe_decrypt_wasm(7, 4, 101, ct2).expect("decrypt");
    assert_eq!(decrypted.to_vec(), vec![6, 7]);
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
