//! WASM helpers for drawing bytes from the platform secure RNG (`getrandom` / Web Crypto).
//!
//! Random bytes are copied into a [`js_sys::Uint8Array`] after being held in a
//! [`zeroize::Zeroizing`] buffer on the Rust side so the intermediate `Vec` is cleared on drop.
//! Callers should still overwrite sensitive random output in `JavaScript` when discarding it.

#![allow(missing_docs)]

extern crate alloc;

use js_sys::Uint8Array;
use rand_core::TryRng;
use wasm_bindgen::prelude::{
    JsValue,
    wasm_bindgen,
};
use zeroize::Zeroizing;

use crate::new_secure_rng;

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_RANDOM", e)
}

/// Fill `len` bytes from [`new_secure_rng`] (`WebAssembly` uses `getrandom` `wasm_js` backend).
#[wasm_bindgen(js_name = secureRandomBytes)]
pub fn secure_random_bytes(len: usize) -> Result<Uint8Array, JsValue> {
    let len_u32 = u32::try_from(len)
        .map_err(|_| js_err("requested length exceeds maximum supported on WASM"))?;
    let mut rng = new_secure_rng().map_err(js_err)?;
    let mut out = Zeroizing::new(alloc::vec![0u8; len]);
    rng.try_fill_bytes(&mut out)
        .map_err(|_| js_err("failed to fill random bytes"))?;
    let array = Uint8Array::new_with_length(len_u32);
    array.copy_from(&out);
    Ok(array)
}
