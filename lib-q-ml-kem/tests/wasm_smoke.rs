//! wasm-bindgen-test smoke: ML-KEM JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ml_kem::wasm::{
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_generate_keypair,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ml_kem_round_trip_wasm() {
    const VARIANT: u8 = 1;
    let kp = ml_kem_generate_keypair(VARIANT).expect("keygen");
    let enc = ml_kem_encapsulate(VARIANT, &kp.public_key()).expect("encap");
    let ss_recv = ml_kem_decapsulate(VARIANT, &kp.secret_key(), &enc.ciphertext()).expect("decap");
    assert_eq!(ss_recv, enc.shared_secret());
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
