//! WASM bindings for experimental toy FHE (`@lib-q/fhe`).

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use js_sys::{
    Int32Array,
    Uint8Array,
};
use serde::{
    Deserialize,
    Serialize,
};
use wasm_bindgen::prelude::*;

use crate::{
    Ciphertext,
    EvalOp,
    FheParams,
    decrypt,
    encrypt,
    eval,
    fhe_keygen,
};

fn js_err(e: impl core::fmt::Display) -> JsValue {
    lib_q_core::wasm_common::wasm_js_error("LIB_Q_FHE", e)
}

#[derive(Serialize, Deserialize)]
struct FheKeygenResult {
    seed: String,
    dimension: u32,
    modulus: i32,
}

#[derive(Serialize, Deserialize)]
struct FheCiphertextWire {
    dimension: u32,
    modulus: i32,
    nonce: String,
    #[serde(rename = "plaintextLen")]
    plaintext_len: u32,
    body: Vec<i32>,
    mask: Vec<i32>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
enum EvalOpWire {
    AddConstant { value: i32 },
    AddCiphertext { ciphertext: FheCiphertextWire },
    MulConstant { value: i32 },
}

fn ciphertext_to_wire(ct: &Ciphertext, plaintext_len: u32) -> FheCiphertextWire {
    FheCiphertextWire {
        dimension: ct.params.dimension as u32,
        modulus: ct.params.modulus,
        nonce: ct.nonce.to_string(),
        plaintext_len,
        body: ct.body.clone(),
        mask: ct.mask.clone(),
    }
}

fn ciphertext_from_wire(wire: &FheCiphertextWire) -> Result<Ciphertext, JsValue> {
    Ok(Ciphertext {
        params: FheParams {
            dimension: wire.dimension as usize,
            modulus: wire.modulus,
        },
        nonce: wire
            .nonce
            .parse::<u64>()
            .map_err(|_| js_err("invalid ciphertext nonce"))?,
        body: wire.body.clone(),
        mask: wire.mask.clone(),
    })
}

fn plaintext_len_from_wire(wire: &FheCiphertextWire) -> usize {
    let dim = wire.dimension as usize;
    let len = wire.plaintext_len as usize;
    if len == 0 || len > dim {
        dim
    } else {
        len
    }
}

fn eval_op_from_wire(op: &EvalOpWire) -> Result<EvalOp, JsValue> {
    match op {
        EvalOpWire::AddConstant { value } => Ok(EvalOp::AddConstant(*value)),
        EvalOpWire::MulConstant { value } => Ok(EvalOp::MulConstant(*value)),
        EvalOpWire::AddCiphertext { ciphertext } => {
            Ok(EvalOp::AddCiphertext(ciphertext_from_wire(ciphertext)?))
        }
    }
}

fn int32_array_to_vec(arr: &Int32Array) -> Vec<i32> {
    let mut out = vec![0i32; arr.length() as usize];
    arr.copy_to(&mut out);
    out
}

/// Deterministic keygen from `(seed, dimension, modulus)`; returns JSON params.
#[wasm_bindgen(js_name = fheKeygen)]
pub fn fhe_keygen_wasm(seed: u64, dimension: u32, modulus: i32) -> Result<JsValue, JsValue> {
    let key = fhe_keygen(seed, dimension as usize, modulus);
    let out = FheKeygenResult {
        seed: seed.to_string(),
        dimension,
        modulus: key.params.modulus,
    };
    serde_wasm_bindgen::to_value(&out).map_err(js_err)
}

/// Encrypt plaintext coefficients (`Int32Array`) with key seed and nonce.
#[wasm_bindgen(js_name = fheEncrypt)]
pub fn fhe_encrypt_wasm(
    seed: u64,
    dimension: u32,
    modulus: i32,
    plaintext: &Int32Array,
    nonce: u64,
) -> Result<JsValue, JsValue> {
    let key = fhe_keygen(seed, dimension as usize, modulus);
    let plaintext = int32_array_to_vec(plaintext);
    let plaintext_len = plaintext.len() as u32;
    let ct = encrypt(&key, &plaintext, nonce);
    serde_wasm_bindgen::to_value(&ciphertext_to_wire(&ct, plaintext_len)).map_err(js_err)
}

/// Homomorphic evaluation; `opJson` is tagged JSON (`addConstant`, `mulConstant`, `addCiphertext`).
#[wasm_bindgen(js_name = fheEval)]
pub fn fhe_eval_wasm(ciphertext_json: JsValue, op_json: JsValue) -> Result<JsValue, JsValue> {
    let wire: FheCiphertextWire =
        serde_wasm_bindgen::from_value(ciphertext_json).map_err(js_err)?;
    let ct = ciphertext_from_wire(&wire)?;
    let op_wire: EvalOpWire = serde_wasm_bindgen::from_value(op_json).map_err(js_err)?;
    let plaintext_len = wire.plaintext_len;
    let out = eval(&ct, eval_op_from_wire(&op_wire)?);
    serde_wasm_bindgen::to_value(&ciphertext_to_wire(&out, plaintext_len)).map_err(js_err)
}

/// Decrypt ciphertext JSON with key `(seed, dimension, modulus)`; returns `Int32Array`.
#[wasm_bindgen(js_name = fheDecrypt)]
pub fn fhe_decrypt_wasm(
    seed: u64,
    dimension: u32,
    modulus: i32,
    ciphertext_json: JsValue,
) -> Result<Int32Array, JsValue> {
    let wire: FheCiphertextWire =
        serde_wasm_bindgen::from_value(ciphertext_json).map_err(js_err)?;
    let key = fhe_keygen(seed, dimension as usize, modulus);
    let ct = ciphertext_from_wire(&wire)?;
    let plain = decrypt(&key, &ct);
    let len = plaintext_len_from_wire(&wire);
    let out = Int32Array::new_with_length(len as u32);
    out.copy_from(&plain[..len]);
    Ok(out)
}

/// Serialize ciphertext JSON to canonical bytes (`Uint8Array`).
#[wasm_bindgen(js_name = fheCiphertextToBytes)]
pub fn fhe_ciphertext_to_bytes_wasm(ciphertext_json: JsValue) -> Result<Uint8Array, JsValue> {
    let wire: FheCiphertextWire =
        serde_wasm_bindgen::from_value(ciphertext_json).map_err(js_err)?;
    let ct = ciphertext_from_wire(&wire)?;
    let bytes = ct.to_bytes();
    let out = Uint8Array::new_with_length(bytes.len() as u32);
    out.copy_from(&bytes);
    Ok(out)
}
