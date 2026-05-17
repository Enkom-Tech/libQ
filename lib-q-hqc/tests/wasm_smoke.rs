//! wasm-bindgen-test smoke for wasm32 (HQC wasm feature set in CI).

#[cfg(target_arch = "wasm32")]
use std::boxed::Box;

#[cfg(target_arch = "wasm32")]
use lib_q_core::{
    Algorithm,
    CryptoProvider,
    KemContext,
};
#[cfg(target_arch = "wasm32")]
use lib_q_hqc::LibQHqcProvider;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn hqc_wasm_smoke() {
    let provider = LibQHqcProvider::new().expect("provider");
    let mut ctx = KemContext::with_provider(Box::new(provider) as Box<dyn CryptoProvider>);

    let keypair = ctx
        .generate_keypair(Algorithm::Hqc128, None)
        .expect("keygen");
    let (ciphertext, sender_ss) = ctx
        .encapsulate(Algorithm::Hqc128, keypair.public_key(), None)
        .expect("encapsulate");
    let receiver_ss = ctx
        .decapsulate(Algorithm::Hqc128, keypair.secret_key(), &ciphertext)
        .expect("decapsulate");
    assert_eq!(sender_ss, receiver_ss);

    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0x01;
    match ctx.decapsulate(Algorithm::Hqc128, keypair.secret_key(), &bad_ct) {
        Ok(bad_ss) => assert_ne!(
            bad_ss, sender_ss,
            "implicit rejection: corrupted ciphertext must not recover sender shared secret"
        ),
        Err(_) => { /* explicit rejection is acceptable */ }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
