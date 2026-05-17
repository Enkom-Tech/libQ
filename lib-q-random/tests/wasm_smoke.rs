//! wasm-bindgen-test smoke for wasm32 (lib-q-random wasm feature).

#[cfg(target_arch = "wasm32")]
use lib_q_random::new_secure_rng;
#[cfg(target_arch = "wasm32")]
use rand_core::TryRng;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn random_wasm_smoke() {
    let mut rng = new_secure_rng().expect("secure rng");
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    rng.try_fill_bytes(&mut out_a).expect("fill a");
    rng.try_fill_bytes(&mut out_b).expect("fill b");

    assert!(
        out_a.iter().any(|b| *b != 0),
        "entropy buffer should not be all zero"
    );
    assert_ne!(out_a, out_b, "sequential outputs should differ");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
