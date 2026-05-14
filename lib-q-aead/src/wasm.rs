//! JavaScript / wasm-bindgen surface for AEAD operations (Saturnin, Duplex-Sponge, Romulus-N).
//!
//! Keys are taken by value and moved into [`lib_q_core::AeadKey`], which clears its backing buffer
//! on drop. JavaScript callers should not retain or log copies of key material passed into these
//! functions.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use lib_q_core::api::AeadOperations;
use lib_q_core::{
    AeadKey,
    Nonce,
};
use wasm_bindgen::prelude::*;

use crate::{
    Algorithm,
    AlgorithmCategory,
    LibQAeadProvider,
};

fn js_err(msg: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_AEAD", msg)
}

fn parse_algorithm(name: &str) -> Result<Algorithm, JsValue> {
    let a = match name.trim() {
        "Saturnin" | "saturnin" => Algorithm::Saturnin,
        "DuplexSpongeAead" | "Duplex-Sponge-AEAD" | "duplex" => Algorithm::DuplexSpongeAead,
        "RomulusN" | "Romulus-N" | "romulus-n" | "romulus" => Algorithm::RomulusN,
        other => {
            return Err(js_err(format!(
                "unknown AEAD algorithm '{other}'; use Saturnin, DuplexSpongeAead, or RomulusN"
            )));
        }
    };
    if a.category() != AlgorithmCategory::Aead {
        return Err(js_err("internal: parsed non-AEAD"));
    }
    Ok(a)
}

/// AEAD encrypt: `algorithm` is `Saturnin`, `DuplexSpongeAead`, or `RomulusN`.
#[wasm_bindgen]
pub fn aead_encrypt(
    algorithm: &str,
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let alg = parse_algorithm(algorithm)?;
    let provider = LibQAeadProvider::new().map_err(js_err)?;
    let k = AeadKey::new(key);
    let n = Nonce::new(nonce);
    let ad = if associated_data.is_empty() {
        None
    } else {
        Some(associated_data.as_slice())
    };
    provider
        .encrypt(alg, &k, &n, &plaintext, ad)
        .map_err(js_err)
}

/// AEAD decrypt (same `algorithm` names as [`aead_encrypt`]).
#[wasm_bindgen]
pub fn aead_decrypt(
    algorithm: &str,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let alg = parse_algorithm(algorithm)?;
    let provider = LibQAeadProvider::new().map_err(js_err)?;
    let k = AeadKey::new(key);
    let n = Nonce::new(nonce);
    let ad = if associated_data.is_empty() {
        None
    } else {
        Some(associated_data.as_slice())
    };
    provider
        .decrypt(alg, &k, &n, &ciphertext, ad)
        .map_err(js_err)
}

/// Array of AEAD algorithm names available in this build (native JS array of strings).
#[wasm_bindgen]
pub fn aead_available_algorithms() -> Result<JsValue, JsValue> {
    let names: Vec<String> = crate::available_algorithms()
        .into_iter()
        .map(|a| format!("{a:?}"))
        .collect();
    serde_wasm_bindgen::to_value(&names).map_err(js_err)
}
