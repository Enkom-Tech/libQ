//! wasm-bindgen-test smoke: blind PCS demo on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_blind_pcs::wasm::{
    blind_commit_wasm,
    blind_verify_bytes_wasm,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn blind_pcs_round_trip_wasm() {
    let message = b"wasm-blind-pcs-message";
    let blind = b"wasm-blind-factor-32-bytes-long!!";
    let commitment = blind_commit_wasm(message, blind);
    let commitment_bytes: Vec<u8> = commitment.to_vec();
    assert!(blind_verify_bytes_wasm(&commitment_bytes, message, blind).expect("verify"));
    assert!(!blind_verify_bytes_wasm(&commitment_bytes, b"tampered", blind).expect("verify bad"));
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
