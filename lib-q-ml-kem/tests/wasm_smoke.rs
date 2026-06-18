//! wasm-bindgen-test smoke: ML-KEM JS API on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_ml_kem::wasm::{
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_generate_keypair,
    ml_kem_generate_keypair_with_seed,
    ml_kem_keypair_from_seed,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ml_kem_round_trip_wasm() {
    const VARIANT: u8 = 1;
    let kp = ml_kem_generate_keypair(VARIANT).expect("keygen");
    let sk = kp.secret_key().to_vec();
    let enc = ml_kem_encapsulate(VARIANT, &kp.public_key()).expect("encap");
    let ss_recv = ml_kem_decapsulate(VARIANT, &sk, &enc.ciphertext()).expect("decap");
    assert_eq!(ss_recv.to_vec(), enc.shared_secret().to_vec());
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn ml_kem_seed_round_trip_wasm() {
    const VARIANT: u8 = 1;
    let kp = ml_kem_generate_keypair_with_seed(VARIANT).expect("keygen+seed");
    let seed = kp.seed().to_vec();
    assert_eq!(seed.len(), 64);

    // Reconstruct from the 64-byte seed; keys must be byte-identical.
    let restored = ml_kem_keypair_from_seed(VARIANT, &seed).expect("from_seed");
    assert_eq!(restored.secret_key().to_vec(), kp.secret_key().to_vec());
    assert_eq!(restored.public_key(), kp.public_key());

    // ...and functionally equivalent end to end.
    let enc = ml_kem_encapsulate(VARIANT, &kp.public_key()).expect("encap");
    let ss_recv = ml_kem_decapsulate(VARIANT, &restored.secret_key().to_vec(), &enc.ciphertext())
        .expect("decap");
    assert_eq!(ss_recv.to_vec(), enc.shared_secret().to_vec());
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
