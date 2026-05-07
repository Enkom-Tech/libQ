//! WASM helpers for drawing bytes from the platform secure RNG (`getrandom` / Web Crypto).

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use rand_core::TryRng;
use wasm_bindgen::prelude::{
    JsValue,
    wasm_bindgen,
};

use crate::new_secure_rng;

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_RANDOM", e)
}

/// Fill `len` bytes from [`new_secure_rng`] (`WebAssembly` uses `getrandom` `wasm_js` backend).
#[wasm_bindgen(js_name = secureRandomBytes)]
pub fn secure_random_bytes(len: usize) -> Result<Vec<u8>, JsValue> {
    let mut rng = new_secure_rng().map_err(js_err)?;
    let mut out = vec![0u8; len];
    rng.try_fill_bytes(&mut out)
        .map_err(|_| js_err("failed to fill random bytes"))?;
    Ok(out)
}
