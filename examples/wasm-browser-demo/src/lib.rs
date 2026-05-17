//! Minimal `wasm-pack` surface for ML-DSA-44 (sign + verify smoke) using deterministic seeds.
//!
//! This crate exists as an integration example, not as a general-purpose signing API.

use lib_q_ml_dsa::constants::{
    KEY_GENERATION_RANDOMNESS_SIZE,
    SIGNING_RANDOMNESS_SIZE,
};
use lib_q_ml_dsa::ml_dsa_44::portable::{
    generate_key_pair,
    sign,
    verify,
};
use wasm_bindgen::prelude::*;

/// Run a fixed-seed ML-DSA-44 sign/verify round-trip; returns `true` on success.
#[wasm_bindgen]
pub fn wasm_smoke_ml_dsa_sign_verify() -> Result<bool, JsValue> {
    let seed = [7u8; KEY_GENERATION_RANDOMNESS_SIZE];
    let kp = generate_key_pair(seed);
    let message = b"libQ wasm browser demo";
    let sig_randomness = [9u8; SIGNING_RANDOMNESS_SIZE];
    let signature = sign(&kp.signing_key, message, b"", sig_randomness)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    verify(&kp.verification_key, message, b"", &signature)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(true)
}
