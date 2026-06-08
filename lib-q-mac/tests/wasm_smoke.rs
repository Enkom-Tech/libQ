//! wasm-bindgen-test smoke: qCW-MAC JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_mac::wasm::{
    qcw_mac_generate_key,
    qcw_mac_sign,
    qcw_mac_verify,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn qcw_mac_round_trip_wasm() {
    let key = qcw_mac_generate_key().expect("keygen");
    let key_bytes: Vec<u8> = key.to_vec();
    let msg = b"wasm-smoke-message";
    let ad = b"wasm-smoke-ad";
    let tag = qcw_mac_sign(&key_bytes, msg, ad).expect("sign");
    let tag_bytes: Vec<u8> = tag.to_vec();
    assert!(qcw_mac_verify(&key_bytes, msg, ad, &tag_bytes).expect("verify"));
    assert!(!qcw_mac_verify(&key_bytes, b"tampered", ad, &tag_bytes).expect("verify tampered"));
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
