//! wasm-bindgen-test smoke for wasm32 (ZKP wasm stack).

#[cfg(target_arch = "wasm32")]
use lib_q_zkp::api::{
    prove_preimage,
    verify_preimage,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn zkp_wasm_smoke() {
    let secret = b"wasm-zkp-secret";
    let proof = prove_preimage(secret).expect("prove preimage");
    let ok = verify_preimage(&proof, secret).expect("verify");
    assert!(ok, "proof must verify for matching statement");

    let mismatch = verify_preimage(&proof, b"wrong-secret").expect("verify mismatch");
    assert!(!mismatch, "proof must fail for mismatched statement");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
