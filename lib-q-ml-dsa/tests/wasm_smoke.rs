//! wasm-bindgen-test smoke: ML-DSA-65 JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ml_dsa::wasm::{
    generate_key_pair,
    sign,
    verify,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ml_dsa_65_round_trip_wasm() {
    let kp = generate_key_pair().expect("keygen");
    let sk = kp.secret_key().to_vec();
    let pk = kp.public_key();
    let message = b"wasm-ml-dsa-65-smoke";
    let context: &[u8] = b"";

    let signature = sign(&sk, message, context).expect("sign");
    assert!(verify(&pk, message, context, &signature).expect("verify"));

    // Tampering with the message must invalidate the signature, not error.
    assert!(!verify(&pk, b"wrong-message", context, &signature).expect("verify tampered"));

    // A signature from a different key pair must not verify.
    let kp2 = generate_key_pair().expect("keygen2");
    assert!(!verify(&kp2.public_key(), message, context, &signature).expect("verify wrong key"));
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
