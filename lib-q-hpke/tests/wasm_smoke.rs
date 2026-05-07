//! wasm-bindgen-test smoke for wasm32 (HPKE wasm + ML-KEM).

#[cfg(target_arch = "wasm32")]
use std::boxed::Box;

#[cfg(target_arch = "wasm32")]
use lib_q_core::{
    Algorithm,
    CryptoProvider,
    KemContext,
};
#[cfg(target_arch = "wasm32")]
use lib_q_hpke::HpkeContext;
#[cfg(target_arch = "wasm32")]
use lib_q_kem::LibQKemProvider;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn hpke_wasm_smoke() {
    let provider = LibQKemProvider::new().expect("kem provider");
    let mut kem_ctx = KemContext::with_provider(Box::new(provider) as Box<dyn CryptoProvider>);
    let recipient_kp = kem_ctx
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("recipient keypair");

    let provider = LibQKemProvider::new().expect("kem provider");
    let mut hpke = HpkeContext::with_provider(Box::new(provider) as Box<dyn CryptoProvider>);
    let info = b"wasm-hpke-info";
    let aad = b"wasm-hpke-aad";
    let plaintext = b"wasm-hpke-plaintext";

    let (enc, ciphertext) = hpke
        .seal(recipient_kp.public_key(), info, aad, plaintext)
        .expect("seal");
    let opened = hpke
        .open(&enc, recipient_kp.secret_key(), info, aad, &ciphertext)
        .expect("open");
    assert_eq!(opened, plaintext);

    assert!(
        hpke.open(
            &enc,
            recipient_kp.secret_key(),
            info,
            b"wrong-aad",
            &ciphertext
        )
        .is_err(),
        "open with wrong AAD must fail"
    );

    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0x01;
    assert!(
        hpke.open(&enc, recipient_kp.secret_key(), info, aad, &bad_ct)
            .is_err(),
        "open with corrupted ciphertext must fail"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
