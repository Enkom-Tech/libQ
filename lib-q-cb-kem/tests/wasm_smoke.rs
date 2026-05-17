//! wasm-bindgen-test smoke for wasm32 (CB-KEM wasm + one parameter set).

#[cfg(target_arch = "wasm32")]
use lib_q_cb_kem::{
    CRYPTO_BYTES,
    decapsulate_boxed,
    encapsulate_boxed,
    keypair_boxed,
};
#[cfg(target_arch = "wasm32")]
use lib_q_random::LibQRng;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn cb_kem_wasm_smoke() {
    let mut rng = LibQRng::new_secure().expect("secure rng");
    let (public_key, secret_key) = keypair_boxed(&mut rng);
    let (ciphertext, sender_ss) = encapsulate_boxed(&public_key, &mut rng);
    let receiver_ss = decapsulate_boxed(&ciphertext, &secret_key);
    assert_eq!(sender_ss.as_ref(), receiver_ss.as_ref());

    let mut corrupted = ciphertext.as_array().to_owned();
    corrupted[0] ^= 0x01;
    let bad_ct = lib_q_cb_kem::Ciphertext::from(corrupted);
    let bad_ss = decapsulate_boxed(&bad_ct, &secret_key);
    assert_eq!(bad_ss.as_ref().len(), CRYPTO_BYTES);
    assert_ne!(
        bad_ss.as_ref(),
        sender_ss.as_ref(),
        "shared secret must not match after ciphertext tampering"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
