//! WASM bindings for experimental blind PCS demo (`@lib-q/blind-pcs`).

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::{
    blind_commit,
    blind_open,
    verify,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_BLIND_PCS", e)
}

fn bytes_to_uint8_array(bytes: &[u8]) -> Uint8Array {
    let n = u32::try_from(bytes.len()).expect("length exceeds Uint8Array maximum");
    let out = Uint8Array::new_with_length(n);
    out.copy_from(bytes);
    out
}

fn parse_commitment(commitment: &[u8]) -> Result<[u8; 32], JsValue> {
    commitment
        .try_into()
        .map_err(|_| js_err("commitment must be exactly 32 bytes"))
}

/// Compute blind commitment `H(message || blind)` (32-byte `Uint8Array`).
#[wasm_bindgen(js_name = blindCommit)]
pub fn blind_commit_wasm(message: &[u8], blind: &[u8]) -> Uint8Array {
    let commitment = blind_commit(message, blind);
    bytes_to_uint8_array(&commitment)
}

/// Open a commitment; returns `{ messageHex, blindHex }` JSON object.
#[wasm_bindgen(js_name = blindOpen)]
pub fn blind_open_wasm(message: &[u8], blind: &[u8]) -> Result<JsValue, JsValue> {
    let opening = blind_open(message, blind);
    let out = serde_json::json!({
        "messageHex": hex_encode(&opening.message),
        "blindHex": hex_encode(&opening.blind),
    });
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Verify commitment against an opening supplied as hex strings in JSON `{ messageHex, blindHex }`.
#[wasm_bindgen(js_name = blindVerify)]
pub fn blind_verify_wasm(
    commitment: &[u8],
    message_hex: &str,
    blind_hex: &str,
) -> Result<bool, JsValue> {
    let commitment = parse_commitment(commitment)?;
    let message = hex_decode(message_hex.trim()).map_err(js_err)?;
    let blind = hex_decode(blind_hex.trim()).map_err(js_err)?;
    let opening = blind_open(&message, &blind);
    Ok(verify(&commitment, &opening))
}

/// Verify with raw byte slices (no hex decoding).
#[wasm_bindgen(js_name = blindVerifyBytes)]
pub fn blind_verify_bytes_wasm(
    commitment: &[u8],
    message: &[u8],
    blind: &[u8],
) -> Result<bool, JsValue> {
    let commitment = parse_commitment(commitment)?;
    let opening = blind_open(message, blind);
    Ok(verify(&commitment, &opening))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, alloc::string::String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string length must be even".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
