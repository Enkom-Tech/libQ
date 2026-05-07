//! WASM exports for high-level ZKP preimage proofs (Poseidon and NIST variants).

#![allow(missing_docs)]

extern crate alloc;

use wasm_bindgen::prelude::*;

use crate::ZkpProof;
use crate::api::{
    prove_preimage,
    prove_preimage_nist,
    verify_preimage,
    verify_preimage_nist,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_ZKP", e)
}

/// Prove knowledge of a secret preimage (Poseidon-128 commitment) as a [`ZkpProof`] object.
#[wasm_bindgen(js_name = zkpProvePreimageJson)]
pub fn zkp_prove_preimage_json(secret: &[u8]) -> Result<JsValue, JsValue> {
    let proof = prove_preimage(secret).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&proof).map_err(js_err)
}

/// Verify a proof object from [`zkp_prove_preimage_json`]; `expected_hash_hex` is 32-byte hash.
#[wasm_bindgen(js_name = zkpVerifyPreimageJson)]
pub fn zkp_verify_preimage_json(proof: JsValue, expected_hash_hex: &str) -> Result<bool, JsValue> {
    let proof: ZkpProof = serde_wasm_bindgen::from_value(proof).map_err(js_err)?;
    let h = hex::decode(expected_hash_hex.trim()).map_err(js_err)?;
    verify_preimage(&proof, &h).map_err(js_err)
}

/// NIST cSHAKE256 preimage proof as a [`ZkpProof`] object.
#[wasm_bindgen(js_name = zkpProvePreimageNistJson)]
pub fn zkp_prove_preimage_nist_json(secret: &[u8]) -> Result<JsValue, JsValue> {
    let proof = prove_preimage_nist(secret).map_err(js_err)?;
    serde_wasm_bindgen::to_value(&proof).map_err(js_err)
}

/// Verify NIST preimage proof object; `expected_hash_hex` is the 32-byte cSHAKE256 output.
#[wasm_bindgen(js_name = zkpVerifyPreimageNistJson)]
pub fn zkp_verify_preimage_nist_json(
    proof: JsValue,
    expected_hash_hex: &str,
) -> Result<bool, JsValue> {
    let proof: ZkpProof = serde_wasm_bindgen::from_value(proof).map_err(js_err)?;
    let h = hex::decode(expected_hash_hex.trim()).map_err(js_err)?;
    verify_preimage_nist(&proof, &h).map_err(js_err)
}
