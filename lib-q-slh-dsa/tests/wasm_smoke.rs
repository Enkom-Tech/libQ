//! wasm-bindgen-test smoke for wasm32 (SLH-DSA wasm feature).

#[cfg(target_arch = "wasm32")]
use lib_q_random::new_secure_rng;
#[cfg(target_arch = "wasm32")]
use lib_q_slh_dsa::{
    Shake128f,
    SigningKey,
};
#[cfg(target_arch = "wasm32")]
use signature::{
    Keypair,
    Signer,
    Verifier,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn slh_dsa_wasm_smoke() {
    let mut rng = new_secure_rng().expect("secure rng");
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let message = b"wasm-slh-dsa-smoke";
    let signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature).is_ok());
    assert!(verifying_key.verify(b"wrong-message", &signature).is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
