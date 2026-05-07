//! wasm-bindgen-test smoke: Legendre PRF pilot on wasm32.

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use crypto_bigint::U256;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use lib_q_prf::{
    LegendreKey256,
    LegendrePrfParams256,
    legendre_prf_u256,
};
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
#[wasm_bindgen_test]
fn prf_legendre_pilot_wasm() {
    let params = LegendrePrfParams256::pilot();
    let key = LegendreKey256::derive_from_seed(b"wasm-smoke-prf", &params).expect("key");
    let x = U256::from(7u32);
    let _ = legendre_prf_u256(&key, &x, &params).expect("prf");
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[test]
fn wasm_smoke_skipped_on_native_host() {}
