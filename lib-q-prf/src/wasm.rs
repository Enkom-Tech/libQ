//! WASM bindings for pilot Legendre / Gold PRFs (256-bit field).

#![allow(missing_docs)]

extern crate alloc;

use alloc::format;

use crypto_bigint::U256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    GoldKey256,
    GoldPrfParams256,
    LegendreKey256,
    LegendrePrfParams256,
    gold_prf_u256,
    legendre_prf_u256,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_PRF", e)
}

/// Legendre PRF on the 256-bit pilot modulus; `key` and `x` are **big-endian** 32-byte field elements (64 hex chars each).
#[wasm_bindgen(js_name = legendrePrfU256BeHex)]
pub fn legendre_prf_u256_be_hex(key_be_hex: &str, x_be_hex: &str) -> Result<i8, JsValue> {
    let params = LegendrePrfParams256::pilot();
    let kb = Zeroizing::new(hex::decode(key_be_hex.trim()).map_err(js_err)?);
    let xb = hex::decode(x_be_hex.trim()).map_err(js_err)?;
    if kb.len() != 32 || xb.len() != 32 {
        return Err(js_err(
            "key and x must be 32 bytes (64 hex chars) big-endian",
        ));
    }
    let k = U256::from_be_slice(kb.as_slice());
    let x = U256::from_be_slice(&xb);
    let key = LegendreKey256::from_uint(k, &params).map_err(|e| js_err(format!("{e:?}")))?;
    legendre_prf_u256(&key, &x, &params).map_err(|e| js_err(format!("{e:?}")))
}

/// Gold PRF on the 256-bit pilot parameters; inputs are **big-endian** 32-byte field elements.
/// Returns hex-encoded 32-byte little-endian output residue.
#[wasm_bindgen(js_name = goldPrfU256BeHex)]
pub fn gold_prf_u256_be_hex(key_be_hex: &str, x_be_hex: &str) -> Result<JsValue, JsValue> {
    let params = GoldPrfParams256::pilot();
    let kb = Zeroizing::new(hex::decode(key_be_hex.trim()).map_err(js_err)?);
    let xb = hex::decode(x_be_hex.trim()).map_err(js_err)?;
    if kb.len() != 32 || xb.len() != 32 {
        return Err(js_err(
            "key and x must be 32 bytes (64 hex chars) big-endian",
        ));
    }
    let k = U256::from_be_slice(kb.as_slice());
    let x = U256::from_be_slice(&xb);
    let key = GoldKey256::from_uint(k, &params).map_err(|e| js_err(format!("{e:?}")))?;
    let out = gold_prf_u256(&key, &x, &params).map_err(|e| js_err(format!("{e:?}")))?;
    let json = serde_json::json!({ "output_hex": hex::encode(out) });
    serde_wasm_bindgen::to_value(&json).map_err(js_err)
}
