//! wasm-bindgen-test smoke: double-KEM JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_double_kem::wasm::{
    double_kem_decap,
    double_kem_encap_hex,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ml_kem::{
    EncodedSizeUser,
    KemCore,
    MlKem768,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_random::new_deterministic_rng;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use serde_wasm_bindgen::from_value;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen::JsValue;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn double_kem_round_trip_wasm() {
    let mut rng = new_deterministic_rng([0x64; 32]);
    let (dk_a, ek_a) = MlKem768::generate(&mut rng);
    let (dk_b, ek_b) = MlKem768::generate(&mut rng);
    let ek_a_hex = hex_encode(ek_a.as_bytes().as_slice());
    let ek_b_hex = hex_encode(ek_b.as_bytes().as_slice());
    let dk_a_hex = hex_encode(dk_a.as_bytes().as_slice());
    let dk_b_hex = hex_encode(dk_b.as_bytes().as_slice());

    let encap_js = double_kem_encap_hex(&ek_a_hex, &ek_b_hex).expect("encap");
    let encap: serde_json::Value = from_value(encap_js).expect("parse encap json");
    let wire_hex = encap["wireHex"].as_str().expect("wireHex");
    let shared_hex = encap["sharedSecretHex"].as_str().expect("sharedSecretHex");

    let wire_bytes: Vec<u8> = (0..wire_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wire_hex[i..i + 2], 16).expect("wire hex"))
        .collect();

    let ss_recv = double_kem_decap(&wire_bytes, &dk_a_hex, &dk_b_hex).expect("decap");
    let ss_recv_hex = hex_encode(&ss_recv.to_vec());
    assert_eq!(ss_recv_hex, shared_hex);
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
