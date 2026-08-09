//! wasm-bindgen-test smoke: `lib_q_core::wasm::error` JsValue-producing paths.
//!
//! These functions build a `wasm_bindgen::JsValue`, which aborts the process natively (observed
//! STATUS_STACK_BUFFER_OVERRUN) outside a real wasm32 runtime — so they must only ever execute
//! under `wasm-pack test --node` on `wasm32-unknown-unknown`, never as a plain `#[test]` on a
//! native host. Run with:
//!   wasm-pack test --node lib-q-core --features wasm

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_core::error::Error;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_core::wasm::error::{
    error_to_js_value,
    parse_algorithm_wasm,
    secure_serialize,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn error_conversion_wasm() {
    let error = Error::InvalidAlgorithm { algorithm: "test" };
    let js_error = error_to_js_value(error);
    assert!(js_error.is_string());
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn algorithm_parsing_wasm() {
    assert!(parse_algorithm_wasm("sha3-256").is_ok());
    assert_eq!(
        parse_algorithm_wasm("mldsa65").unwrap(),
        lib_q_core::api::Algorithm::MlDsa65
    );
    assert_eq!(
        parse_algorithm_wasm("ML-DSA-65").unwrap(),
        lib_q_core::api::Algorithm::MlDsa65
    );
    assert_eq!(
        parse_algorithm_wasm("slh-dsa-shake256-128f-robust").unwrap(),
        lib_q_core::api::Algorithm::SlhDsaShake256128fRobust
    );
    assert_eq!(
        parse_algorithm_wasm("SlhDsaShake256128fRobust").unwrap(),
        lib_q_core::api::Algorithm::SlhDsaShake256128fRobust
    );
    assert!(parse_algorithm_wasm("invalid").is_err());
    assert!(parse_algorithm_wasm(&"a".repeat(100)).is_err());
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn secure_serialization_wasm() {
    let value = serde_json::json!({"test": "value"});
    let result = secure_serialize(&value);
    assert!(result.is_ok());
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
