//! WASM bindings for qCW-MAC (`@lib-q/mac`).

#![allow(missing_docs)]

extern crate alloc;

use js_sys::Uint8Array;
use lib_q_random::new_secure_rng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::profile::{
    QCW_MAC_KEY_BYTES,
    QCW_MAC_TAG_BYTES,
};
use crate::{
    QcwMac,
    QcwMacKey,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_MAC", e)
}

fn bytes_to_uint8_array(secret: &[u8]) -> Uint8Array {
    let n = u32::try_from(secret.len()).expect("length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(secret);
    out
}

fn parse_key(key: &[u8]) -> Result<QcwMacKey, JsValue> {
    if key.len() != QCW_MAC_KEY_BYTES {
        return Err(js_err("MAC key must be exactly 32 bytes"));
    }
    let mut bytes = [0u8; QCW_MAC_KEY_BYTES];
    bytes.copy_from_slice(key);
    Ok(QcwMacKey::from_bytes(bytes))
}

/// Key size in bytes (32).
#[wasm_bindgen(js_name = qcwMacKeyBytes)]
pub fn qcw_mac_key_bytes() -> u32 {
    QCW_MAC_KEY_BYTES as u32
}

/// Tag size in bytes (32).
#[wasm_bindgen(js_name = qcwMacTagBytes)]
pub fn qcw_mac_tag_bytes() -> u32 {
    QCW_MAC_TAG_BYTES as u32
}

/// Generate a fresh qCW-MAC key (`Uint8Array`, 32 bytes).
#[wasm_bindgen(js_name = qcwMacGenerateKey)]
pub fn qcw_mac_generate_key() -> Result<Uint8Array, JsValue> {
    let mut rng = new_secure_rng().map_err(js_err)?;
    let key = QcwMacKey::generate(&mut rng);
    Ok(bytes_to_uint8_array(key.as_bytes()))
}

/// Sign `(msg, ad)` with `key`; returns authentication tag as `Uint8Array`.
#[wasm_bindgen(js_name = qcwMacSign)]
pub fn qcw_mac_sign(key: &[u8], msg: &[u8], ad: &[u8]) -> Result<Uint8Array, JsValue> {
    let mac_key = parse_key(key)?;
    let tag = Zeroizing::new(QcwMac::sign(&mac_key, msg, ad));
    Ok(bytes_to_uint8_array(tag.as_slice()))
}

/// Constant-time tag verification.
#[wasm_bindgen(js_name = qcwMacVerify)]
pub fn qcw_mac_verify(key: &[u8], msg: &[u8], ad: &[u8], tag: &[u8]) -> Result<bool, JsValue> {
    let mac_key = parse_key(key)?;
    Ok(QcwMac::verify(&mac_key, msg, ad, tag))
}
