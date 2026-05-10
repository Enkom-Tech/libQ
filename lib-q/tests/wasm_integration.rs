//! Cross-crate WASM smoke: umbrella `lib-q` + ML-KEM on `wasm32-unknown-unknown`.
//!
//! Run via `wasm-pack test --node --features wasm,ml-kem --test wasm_integration`.

#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem"))]
use std::boxed::Box;

#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem"))]
use lib_q_core::CryptoProvider;
#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem"))]
use libq::{
    Algorithm,
    KemContext,
    LibQKemProvider,
    wasm::init_wasm,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem"))]
#[wasm_bindgen_test]
fn umbrella_ml_kem_roundtrip_after_init_wasm() {
    init_wasm().expect("init_wasm");
    let provider = LibQKemProvider::new().expect("kem provider");
    let mut kem = KemContext::with_provider(Box::new(provider) as Box<dyn CryptoProvider>);
    let kp = kem
        .generate_keypair(Algorithm::MlKem512, None)
        .expect("keypair");
    let (ct, ss1) = kem
        .encapsulate(Algorithm::MlKem512, kp.public_key(), None)
        .expect("encapsulate");
    let ss2 = kem
        .decapsulate(Algorithm::MlKem512, kp.secret_key(), &ct)
        .expect("decapsulate");
    assert_eq!(ss1, ss2);
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm", feature = "ml-kem")))]
#[test]
fn wasm_integration_skipped_on_native_host() {}
